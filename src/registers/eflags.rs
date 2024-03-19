use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EFlags: u32 {
        /// ID Flag
        const ID = 1 << 21;
        /// Virtual Interrupt Pending
        const VIP = 1 << 20;
        /// Virtual Interrupt Flag
        const VIF = 1 << 19;
        /// Alignment Check / Access Control
        const AC = 1 << 18;
        /// Virtual-8086 Mode
        const VM = 1 << 17;
        /// Resume Flag
        const RF = 1 << 16;
        /// Always 0
        const _bit_15_zero = 1 << 5;
        /// Nested Task
        const NT = 1 << 14;
        /// I/O Privilege Level
        const IOPL = 3 << 12;
        /// Overflow Flag
        const OF = 1 << 11;
        /// Direction Flag
        const DF = 1 << 10;
        /// Interrupt Enable Flag
        const IF = 1 << 9;
        /// Trap Flag
        const TF = 1 << 8;
        /// Sign Flag
        const SF = 1 << 7;
        /// Zero Flag
        const ZF = 1 << 6;
        /// Always 0
        const _bit_5_zero = 1 << 5;
        /// Auxiliary Carry Flag
        const AF = 1 << 4;
        /// Always 0
        const _bit_3_zero = 1 << 3;
        /// Parity Flag
        const PF = 1 << 2;
        /// Always 1
        const _ = 1 << 1;
        /// Carry Flag
        const CF = 1 << 0;

        const _ = !0;
    }
}
