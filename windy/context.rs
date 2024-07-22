use crate::arch::Registers;

#[macro_export]
macro_rules! registers {
    (
        registers => (
            $( $reg:ident ( $val:expr ) ),* $(,)?
        ),
        implement => {
            $( $item:tt )*
        }
    ) => {
        #[repr(usize)]
        #[derive(Debug, Copy, Clone)]
        pub enum Registers {
            IP = usize::MAX,
            SP = usize::MAX - 1,
            $(
                $reg = $val,
            )*
        }

        impl core::convert::TryFrom<usize> for Registers {
            type Error = usize;

            fn try_from(v: usize) -> Result<Self, Self::Error> {
                match v {
                    $(
                        $val => Ok(Self::$reg),
                    )*
                    _ => Err(v),
                }
            }
        }

        impl crate::common::debug::unwind::context::Register for Registers {
            fn name(&self) -> &'static str {
                match self {
                    Registers::IP => "IP",
                    Registers::SP => "SP",
                    $(
                        Self::$reg => stringify!($reg),
                    )*
                }
            }

            $( $item )*
        }
    }
}

#[macro_export]
macro_rules! unwind_context {
    (
        save_registers => {
            $( $reg:ident ),* $(,)?
        },
        stack_pointer => $sp:ident,
        instruction_pointer => $ip:ident
    ) => {
        #[derive(Default, Debug, Copy, Clone)]
        pub struct UnwindContext {
            $(
                #[allow(non_snake_case)]
                $reg: Option<usize>,
            )*
        }

        impl UnwindContext {
            pub fn new() -> Self {
                Self {
                    $(
                        $reg: None,
                    )*
                }
            }
        }

        impl crate::common::debug::unwind::context::Context for UnwindContext {
            fn get_register(&self, register: crate::arch::Registers) -> Option<usize> {
                match register {
                    crate::arch::Registers::IP => self.get_instruction_pointer(),
                    crate::arch::Registers::SP => self.get_stack_pointer(),
                    $(
                        crate::arch::Registers::$reg => self.$reg,
                    )*
                }
            }

            fn set_register(&self, register: crate::arch::Registers, value: usize) -> Result<(), ()> {
                match register {
                    crate::arch::Registers::IP => self.set_instruction_pointer(value),
                    crate::arch::Registers::SP => self.set_stack_pointer(value),
                    $(
                        crate::arch::Registers::$reg => {
                            let mut new = self.clone();
                            new.$reg = Some(value);
                            Ok(())
                        },
                    )*
                }
            }

            fn get_instruction_pointer(&self) -> Option<usize> {
                self.get_register(crate::arch::Registers::$ip)
            }

            fn set_instruction_pointer(&self, value: usize) -> Result<(), ()> {
                self.set_register(crate::arch::Registers::$ip, value)
            }

            fn get_stack_pointer(&self) -> Option<usize> {
                self.get_register(crate::arch::Registers::$sp)
            }

            fn set_stack_pointer(&self, value: usize) -> Result<(), ()> {
                self.set_register(crate::arch::Registers::$sp, value)
            }

            fn save_context(&mut self) {
                use crate::common::debug::unwind::context::Register;
                $(self.$reg = crate::arch::Registers::$reg.get();)*
            }
        }
    };
}

pub trait Register {
    fn get(&self) -> Option<usize>;
    unsafe fn set(&self, value: usize) -> Result<(), ()>;
    fn name(&self) -> &'static str;
}

pub trait Context {
    fn get_register(&self, register: Registers) -> Option<usize>;
    fn set_register(&self, register: Registers, value: usize) -> Result<(), ()>;
    fn get_instruction_pointer(&self) -> Option<usize>;
    fn set_instruction_pointer(&self, value: usize) -> Result<(), ()>;
    fn get_stack_pointer(&self) -> Option<usize>;
    fn set_stack_pointer(&self, value: usize) -> Result<(), ()>;
    fn save_context(&mut self);
}