//! Fixed-size history: the newest `capacity` samples, oldest first.

use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct Ring<T> {
    items: VecDeque<T>,
    capacity: usize,
}

impl<T: Clone> Ring<T> {
    pub fn new(capacity: usize) -> Self {
        Self { items: VecDeque::with_capacity(capacity.max(1)), capacity: capacity.max(1) }
    }

    pub fn push(&mut self, item: T) {
        if self.items.len() == self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(item);
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.items.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_the_oldest_beyond_capacity() {
        let mut r = Ring::new(3);
        assert!(r.to_vec().is_empty());
        for i in 0..5 {
            r.push(i);
        }
        assert_eq!(r.to_vec(), vec![2, 3, 4]);
        let mut one = Ring::new(0);
        one.push('a');
        one.push('b');
        assert_eq!(one.to_vec(), vec!['b'], "capacity is at least one");
    }
}
