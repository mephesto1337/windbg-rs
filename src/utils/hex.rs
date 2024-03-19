use std::fmt;

pub struct Hex<T: fmt::LowerHex>(pub T);

impl<T> fmt::Debug for Hex<T>
where
    T: fmt::LowerHex,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}
