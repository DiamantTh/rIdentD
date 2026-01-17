#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Reply,
    Hide,
    Random,
    RandomNumeric,
    Numeric,
    Forward,
    Spoof,
    SpoofAll,
    SpoofPrivPort,
}

#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    allowed: Vec<Capability>,
}

impl CapabilitySet {
    pub fn new(allowed: Vec<Capability>) -> Self {
        Self { allowed }
    }

    pub fn allows(&self, capability: Capability) -> bool {
        self.allowed.contains(&capability)
    }
}
