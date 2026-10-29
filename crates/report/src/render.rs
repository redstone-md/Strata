use crate::CaseReport;
use strata_case::StoredHit;
use strata_kernel::Timestamp;

pub trait Renderer {
    fn extension(&self) -> &'static str;
    fn render(&self, report: &CaseReport) -> String;
}

pub fn renderer_for(format: &str) -> Option<Box<dyn Renderer>> {
    match format.to_ascii_lowercase().as_str() {
        "md" | "markdown" => Some(Box::new(MarkdownRenderer)),
        "html" => Some(Box::new(HtmlRenderer)),
        "csv" => Some(Box::new(CsvRenderer)),
        "json" => Some(Box::new(JsonRenderer)),
        _ => None,
    }
}

fn when(ts: i64) -> String {
    Timestamp::from_unix_secs(ts).map_or_else(|| ts.to_string(), |t| t.to_string())
}

fn location(h: &StoredHit) -> String {
    match &h.file_path {
        Some(p) => format!("{p} [{}] +{:#x}", h.file_state.as_deref().unwrap_or("?"), h.file_offset.unwrap_or(0)),
        None => format!("raw {:#x}", h.hit.offset),
    }
}

/// Rows shared by the tabular renderers (one definition of the hit columns).
fn hit_row(h: &StoredHit) -> [String; 7] {
    [
        h.evidence.to_string(),
        format!("{:?}", h.hit.category),
        h.hit.label.clone(),
        h.hit.value.clone(),
        h.hit.confidence.to_string(),
        location(h),
        format!("{:#x}", h.hit.offset),
    ]
}

const HIT_HEADERS: [&str; 7] = ["Диск", "Категория", "Тип", "Значение", "Уверенность", "Расположение", "Смещение"];

pub struct MarkdownRenderer;

impl MarkdownRenderer {
    fn escape(s: &str) -> String {
        s.replace('|', "\\|").replace('\n', " ")
    }

    fn table(out: &mut String, hits: &[StoredHit]) {
        out.push_str(&format!("| {} |\n|{}\n", HIT_HEADERS.join(" | "), "---|".repeat(HIT_HEADERS.len())));
        for h in hits {
            let row: Vec<String> = hit_row(h).iter().map(|c| Self::escape(c)).collect();
            out.push_str(&format!("| {} |\n", row.join(" | ")));
        }
    }
}

impl Renderer for MarkdownRenderer {
    fn extension(&self) -> &'static str {
        "md"
    }

    fn render(&self, r: &CaseReport) -> String {
        let mut out = format!("# Отчёт Strata: {}\n\nСформирован: {}\n\n## Носители\n\n", r.case_name, when(r.generated_at));
        for e in &r.evidence {
            out.push_str(&format!(
                "### {} {}\n\n- Источник: `{}`\n- Размер: {} байт\n- Просканировано: {:.1}%{}\n",
                e.id,
                e.label,
                e.location,
                e.bytes,
                e.scanned_fraction * 100.0,
                if e.scan_completed { " (полностью)" } else { "" }
            ));
            for v in &e.volumes {
                out.push_str(&format!("- Раздел: {v}\n"));
            }
            let counts: Vec<String> = e.findings.iter().map(|(c, n)| format!("{c:?}: {n}")).collect();
            out.push_str(&format!("- Находки: {}\n\n", if counts.is_empty() { "нет".into() } else { counts.join(", ") }));
        }
        out.push_str("## Балансы адресов\n\n");
        let used: Vec<_> = r.used_balances().collect();
        if used.is_empty() {
            out.push_str("Ни один найденный адрес не встречается в блокчейне.\n\n");
        }
        for b in used {
            out.push_str(&format!("- `{}` — {:.8} BTC, транзакций: {}\n", b.address, b.balance_btc(), b.tx_count));
        }
        out.push_str("\n## Ключи, кошельки, адреса\n\n");
        Self::table(&mut out, &r.wallet_findings);
        out.push_str("\n## Аккаунты и сервисы\n\n");
        Self::table(&mut out, &r.identity_findings);
        out.push_str("\n## Пересечения между дисками\n\n");
        for s in &r.shared {
            let disks: Vec<String> = s.evidence.iter().map(|e| e.to_string()).collect();
            out.push_str(&format!("- {:?} `{}` — диски {} (встречается {} раз)\n", s.category, Self::escape(&s.value), disks.join(", "), s.occurrences));
        }
        out.push_str("\n## Файлы, которые диски дополняют друг у друга\n\n");
        for c in &r.complements {
            let copies: Vec<String> = c.copies.iter().map(|(e, st, sz)| format!("{e}: {st}, {sz} Б")).collect();
            out.push_str(&format!("- `{}` — {}\n", Self::escape(&c.path), copies.join("; ")));
        }
        out
    }
}

pub struct CsvRenderer;

impl Renderer for CsvRenderer {
    fn extension(&self) -> &'static str {
        "csv"
    }

    fn render(&self, r: &CaseReport) -> String {
        let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let mut out = HIT_HEADERS.iter().map(|h| quote(h)).collect::<Vec<_>>().join(",") + "\n";
        for h in r.wallet_findings.iter().chain(&r.identity_findings) {
            out += &(hit_row(h).iter().map(|c| quote(c)).collect::<Vec<_>>().join(",") + "\n");
        }
        out
    }
}

pub struct JsonRenderer;

impl Renderer for JsonRenderer {
    fn extension(&self) -> &'static str {
        "json"
    }

    fn render(&self, r: &CaseReport) -> String {
        serde_json::to_string_pretty(r).unwrap_or_default()
    }
}

pub struct HtmlRenderer;

impl HtmlRenderer {
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    fn table(hits: &[StoredHit]) -> String {
        let head: String = HIT_HEADERS.iter().map(|h| format!("<th>{h}</th>")).collect();
        let rows: String = hits
            .iter()
            .map(|h| format!("<tr>{}</tr>", hit_row(h).iter().map(|c| format!("<td>{}</td>", Self::esc(c))).collect::<String>()))
            .collect();
        format!("<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
    }
}

const HTML_STYLE: &str = "body{margin:0;padding:32px;background:#0b1424;color:#e6ecf5;font:14px/1.5 'Segoe UI',system-ui,sans-serif}\
h1{font-weight:300;font-size:34px}h2{font-weight:300;margin-top:32px}\
.card{background:rgba(20,32,58,.75);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:20px;margin:12px 0}\
.muted{color:#8a97ad}table{width:100%;border-collapse:collapse;font-size:12px}\
th,td{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left;word-break:break-all}\
th{color:#8a97ad;font-weight:400}.bar{height:6px;border-radius:3px;background:linear-gradient(90deg,#f97316,#facc15,#3b82f6,#22c55e)}";

impl Renderer for HtmlRenderer {
    fn extension(&self) -> &'static str {
        "html"
    }

    fn render(&self, r: &CaseReport) -> String {
        let evidence: String = r
            .evidence
            .iter()
            .map(|e| {
                format!(
                    "<div class='card'><b>{} {}</b><div class='muted'>{}</div><div>{:.2} GB · {:.1}% просканировано</div>\
                     <div class='bar' style='width:{:.1}%'></div></div>",
                    e.id,
                    Self::esc(&e.label),
                    Self::esc(&e.location),
                    e.bytes as f64 / 1e9,
                    e.scanned_fraction * 100.0,
                    e.scanned_fraction * 100.0
                )
            })
            .collect();
        let balances: String = r
            .used_balances()
            .map(|b| format!("<tr><td>{}</td><td>{:.8} BTC</td><td>{}</td></tr>", b.address, b.balance_btc(), b.tx_count))
            .collect();
        format!(
            "<!doctype html><html lang='ru'><head><meta charset='utf-8'><title>Strata — {name}</title><style>{HTML_STYLE}</style></head><body>\
             <h1>{name}</h1><div class='muted'>Сформирован {gen}</div><h2>Носители</h2>{evidence}\
             <h2>Адреса с историей в блокчейне</h2><div class='card'><table>{balances}</table></div>\
             <h2>Ключи, кошельки, адреса</h2><div class='card'>{wallets}</div>\
             <h2>Аккаунты и сервисы</h2><div class='card'>{ids}</div></body></html>",
            name = Self::esc(&r.case_name),
            gen = when(r.generated_at),
            wallets = Self::table(&r.wallet_findings),
            ids = Self::table(&r.identity_findings),
        )
    }
}
