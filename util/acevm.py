import random
from enum import Enum
from reil.definitions import (
    ImmediateOperand,
    TemporaryOperand,
    RegisterOperand,
    _opcode_to_string,
)


class REILRegContext(Enum):
    """
    Enumerated type representing different possible startup register contexts
    """

    # Undefined/custom (used when user provides context)
    undefined = 0
    # All registers = 0
    zeros = 1
    # All registers = 1
    ones = 2
    # All registers = 1,073,741,823 (0x3FFFFFFF, or half of the 32-bit signed max)
    halfmax_signed = 3
    # All registers = 2,147,483,647 (0x7FFFFFFF, or half of the 32-bit unsigned max)
    halfmax_unsigned = 4
    # All registers = -1,073,741,823 (0xC0000001, or half of the 32-bit signed min)
    halfmin_signed = 5
    # All registers = 0x55555555 (0b01010101010101010101010101010101)
    bitweave_one = 6
    # All registers = 0x0F0F0F0F (0b00001111000011110000111100001111)
    bitweave_four = 7
    # Register values count up from zero
    countup = 8
    # Register values count down from 31
    countdown = 9
    # Random permutations (see implementation)
    random1 = 10
    random2 = 11
    random3 = 12
    random4 = 13


class REILMemContext(Enum):
    """
    Enumerated type representing different possible startup memory contexts
    """

    # Undefined/custom (used when user provides context)
    undefined = 0
    # All addresses = 0
    zeros = 1
    # ...
    # TODO: determine if other memory contexts are helpful
    # ...
    # All memory cells have their address as their value
    address = 2


class REILApproximateVM:
    """
    "Approximate" virtual machine for REIL. Designed for fast collection of context changes, not correct execution
    """

    def __init__(
        self,
        reg_context,
        mem_context,
        dynamic_mem=True,
        strict_registers=False,
        int_overflow=True,
    ):
        """
        Constructor
        
        :param strict_registers: set to True to raise a ValueError every time a register is referenced that is not explicitly supported (right now, only x86 is supported). False will allow unsupported registers to be created "on the fly"
        :param int_overflow: set to True to simulate 32-bit signed integer overflow
        """
        # Overflow setup
        self.int_overflow = int_overflow

        # Memory setup
        self.mem_context = mem_context
        self.dynamic_mem = dynamic_mem
        self.memory = {}

        # Register setup
        self.strict_registers = strict_registers
        X86_REG_NAMES = [
            "al",
            "ah",
            "bl",
            "bh",
            "cl",
            "ch",
            "dl",
            "dh",
            "sil",
            "dil",
            "bpl",
            "spl",
            "r8b",
            "r9b",
            "r10b",
            "r11b",
            "r12b",
            "r13b",
            "r14b",
            "r15b",
            "ax",
            "bx",
            "cx",
            "dx",
            "si",
            "di",
            "bp",
            "sp",
            "r8w",
            "r9w",
            "r10w",
            "r11w",
            "r12w",
            "r13w",
            "r14w",
            "r15w",
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "r8d",
            "r9d",
            "r10d",
            "r11d",
            "r12d",
            "r13d",
            "r14d",
            "r15d",
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rip",
            "cf",
            "pf",
            "af",
            "zf",
            "sf",
            "tf",
            "if",
            "df",
            "of",
            "iopl",
            "nt",
            "rf",
            "vm",
            "ac",
            "vif",
            "vip",
            "id",
        ]
        NUM_T_REGS = 32
        NUM_N_REGS = len(X86_REG_NAMES)
        self.reg_context = reg_context
        n_regs = {}

        if not isinstance(reg_context, REILRegContext) and hasattr(
            reg_context, "__getitem__"
        ):
            # Allows user to provide array of registers for custom contexts
            self.reg_context = REILRegContext.undefined
            self.t_regs = reg_context
            self.n_regs = dict(zip(X86_REG_NAMES, reg_context))
        elif reg_context == REILRegContext.zeros:
            self.t_regs = [0] * NUM_T_REGS
            self.n_regs = dict(zip(X86_REG_NAMES, [0] * NUM_N_REGS))
        elif reg_context == REILRegContext.ones:
            self.t_regs = [1] * NUM_T_REGS
            self.n_regs = dict(zip(X86_REG_NAMES, [1] * NUM_N_REGS))
        elif reg_context == REILRegContext.halfmax_signed:
            self.t_regs = [0x3FFFFFFF] * NUM_T_REGS
            self.n_regs = dict(zip(X86_REG_NAMES, [0x3FFFFFFF] * NUM_N_REGS))
        elif reg_context == REILRegContext.halfmax_unsigned:
            self.t_regs = [0x7FFFFFFF] * NUM_T_REGS
            self.n_regs = dict(zip(X86_REG_NAMES, [0x7FFFFFFF] * NUM_N_REGS))
        elif reg_context == REILRegContext.halfmin_signed:
            self.t_regs = [0xC0000001] * NUM_T_REGS
            self.n_regs = dict(zip(X86_REG_NAMES, [0xC0000001] * NUM_N_REGS))
        elif reg_context == REILRegContext.bitweave_one:
            self.t_regs = [0x55555555] * NUM_T_REGS
            self.n_regs = dict(zip(X86_REG_NAMES, [0x55555555] * NUM_N_REGS))
        elif reg_context == REILRegContext.bitweave_four:
            self.t_regs = [0x0F0F0F0F] * NUM_T_REGS
            self.n_regs = dict(zip(X86_REG_NAMES, [0x0F0F0F0F] * NUM_N_REGS))
        elif reg_context == REILRegContext.countup:
            self.t_regs = list(range(NUM_T_REGS))
            self.n_regs = dict(zip(X86_REG_NAMES, list(range(NUM_N_REGS))))
        elif reg_context == REILRegContext.countdown:
            self.t_regs = list(range(NUM_T_REGS - 1, -1, -1))
            self.n_regs = dict(zip(X86_REG_NAMES, list(range(NUM_N_REGS - 1, -1, -1))))
        elif reg_context == REILRegContext.random1:
            self.t_regs = REILApproximateVM.__random_context(NUM_T_REGS, 100)
            self.n_regs = dict(
                zip(X86_REG_NAMES, REILApproximateVM.__random_context(NUM_N_REGS, 101))
            )
        elif reg_context == REILRegContext.random2:
            self.t_regs = REILApproximateVM.__random_context(NUM_T_REGS, 200)
            self.n_regs = dict(
                zip(X86_REG_NAMES, REILApproximateVM.__random_context(NUM_N_REGS, 201))
            )
        elif reg_context == REILRegContext.random3:
            self.t_regs = REILApproximateVM.__random_context(NUM_T_REGS, 300)
            self.n_regs = dict(
                zip(X86_REG_NAMES, REILApproximateVM.__random_context(NUM_N_REGS, 301))
            )
        elif reg_context == REILRegContext.random4:
            self.t_regs = REILApproximateVM.__random_context(NUM_T_REGS, 400)
            self.n_regs = dict(
                zip(X86_REG_NAMES, REILApproximateVM.__random_context(NUM_N_REGS, 401))
            )
        else:
            raise ValueError("Invalid register context")

    @classmethod
    def __random_context(cls, num_regs, seed):
        """
        Deterministic random context generator
        """
        t_regs = [0] * num_regs
        random.seed(seed)
        for s in range(num_regs):
            t_regs[s] = random.randint(-1073741823, 1073741823)
        return t_regs

    def __ovf(self, val):
        """
        Simulates 32-bit signed integer overflow
        """
        maxint = 2147483647
        if not -maxint - 1 <= val <= maxint:
            val = (val + (maxint + 1)) % (2 * (maxint + 1)) - maxint - 1
        return val

    def __set_reg(self, value, reg):
        """
        Stores a value in a register
        """
        if isinstance(reg, TemporaryOperand):
            try:
                self.t_regs[int(reg.name[1:])] = (
                    self.__ovf(value) if self.int_overflow else value
                )
            except IndexError:
                if self.strict_registers:
                    raise ValueError(
                        "Out-of-range temp register accessed while strict register mode enabled"
                    )
                else:
                    # Overflow register
                    self.t_regs[int(reg.name[1:]) % len(self.t_regs)] = (
                        self.__ovf(value) if self.int_overflow else value
                    )

        elif isinstance(reg, RegisterOperand):
            if not self.strict_registers or reg.name in self.n_regs:
                self.n_regs[reg.name] = (
                    self.__ovf(value) if self.int_overflow else value
                )
            else:
                raise ValueError(
                    "Unsupported named register accessed while strict register mode enabled"
                )
        else:
            raise ValueError("Invalid register provided")

    def __resolve_op(self, operand):
        """
        Given an operand, return its value
        """
        if isinstance(operand, ImmediateOperand):
            return operand.value
        elif isinstance(operand, TemporaryOperand):
            try:
                return self.t_regs[int(operand.name[1:])]
            except IndexError:
                if self.strict_registers:
                    raise ValueError(
                        "Out-of-range temp register accessed while strict register mode enabled"
                    )
                else:
                    # Overflow register
                    return self.t_regs[int(operand.name[1:]) % len(self.t_regs)]
        elif isinstance(operand, RegisterOperand):
            try:
                return self.n_regs[operand.name]
            except KeyError:
                if self.strict_registers:
                    raise ValueError(
                        "Unsupported named register accessed while strict register mode enabled"
                    )
                else:
                    # Create register 'on the fly'
                    self.n_regs[operand.name] = 0
                    return self.n_regs[operand.name]
        else:
            raise ValueError("Invalid register provided")

    #### BEGIN INSTRUCTION IMPLEMENTATION ####
    def __add(self, input0, input1, output):
        """
        Adds the two values given in the first and second operand and writes the result to the third operand. 
        The input operands can be literals and register values. The output operand must be a register.
        """
        self.__set_reg(self.__resolve_op(input0) + self.__resolve_op(input1), output)
        return

    def __and(self, input0, input1, output):
        """
        Binary AND operation that connects the first two operands and stores the result in the third operand. 
        The input operands can be literals and register values. The output operand must be a register.
        """
        self.__set_reg(self.__resolve_op(input0) & self.__resolve_op(input1), output)
        return

    def __bisz(self, input0, input1, output):
        """
        Sets a flag depending on whether another value is zero. 
        The input operand can be a literal or a register value. The output operand is a register.
        """
        self.__set_reg(1 if self.__resolve_op(input0) == 0 else 0, output)
        return

    def __bsh(self, input0, input1, output):
        """
        Performs a logical shift on a value. If the second operand is positive, the shift is a left-shift. 
        If the second operand is negative, the shift is a right-shift. The two input operands can be either 
        registers or literals while the output operand must be a register.
        """
        if self.__resolve_op(input1) > 0:
            self.__set_reg(
                self.__resolve_op(input0) << self.__resolve_op(input1), output
            )
        else:
            self.__set_reg(
                self.__resolve_op(input0) >> self.__resolve_op(input1), output
            )
        return

    def __div(self, input0, input1, output):
        """
        Performs an unsigned division on the two input operands. The first input operand is the dividend, 
        the second input operand is the divisor. The two input operands can be either registers or literals 
        while the output operand must be a register.
        
        Imp. Note: output is zero on divide-by-zero
        """
        try:
            self.__set_reg(
                self.__resolve_op(input0) // self.__resolve_op(input1), output
            )
        except ZeroDivisionError:
            self.__set_reg(0, output)
        return

    def __jcc(self, input0, input1, output):
        """
        Conditional jump. Not implemented.
        """
        pass

    def __ldm(self, input0, input1, output):
        """
        Loads a value from memory. The first operand specifies the address to read from. It can be either 
        a register or a literal. The third operand must be a register where the loaded value is stored. 
        The size of the third operand determines how many bytes are read from memory.
        
        Imp. Note: we only read the address specifed, nothing beyond that
        """
        # If dynamic memory is on, we check if that address has been written to yet
        if self.dynamic_mem:
            saddr = str(self.__resolve_op(input0))
            try:
                self.__set_reg(self.memory[saddr], output)
            except KeyError:
                # if it hasn't been written to, we just return the address as the value
                # TODO: IMPLEMENT OTHER MemContexts
                self.__set_reg(self.__resolve_op(input0), output)
        else:
            # if dynamic memory is off, we just return the address as the value
            self.__set_reg(self.__resolve_op(input0), output)
        return

    def __mod(self, input0, input1, output):
        """
        Performs a modulo operation on the first two operands. The two input operands can be either registers 
        or literals while the output operand must be a register.
        
        Imp. Note: output is zero on divide-by-zero
        """
        try:
            self.__set_reg(
                self.__resolve_op(input0) % self.__resolve_op(input1), output
            )
        except ZeroDivisionError:
            self.__set_reg(0, output)
        return

    def __mul(self, input0, input1, output):
        """
        Performs an unsigned multiplication on the two input operands. The two input operands can be either 
        registers or literals while the output operand must be a register.
        """
        self.__set_reg(self.__resolve_op(input0) * self.__resolve_op(input1), output)
        return

    def __nop(self, input0, input1, output):
        """
        Does nothing.
        """
        pass

    def __or(self, input0, input1, output):
        """
        Binary OR operation that connects the first two operands and stores the result in the third operand. 
        The input operands can be literals and register values. The output operand must be a register.
        """
        self.__set_reg(self.__resolve_op(input0) | self.__resolve_op(input1), output)
        return

    def __stm(self, input0, input1, output):
        """
        Stores a value to memory. The first operand is the register value or literal to be stored in memory. 
        The third operand is the register value or literal that contains the memory address where the value is stored. 
        The size of the first operand determines the number of bytes to be written to memory.
        """
        # Only does anything if dynamic memory is on
        if self.dynamic_mem:
            self.memory[str(self.__resolve_op(output))] = self.__resolve_op(input0)
        return

    def __str(self, input0, input1, output):
        """
        Copies a value to a register. The input operand can be either a literal or a register. The output operand must 
        be a register. If the output operand is of a larger size than the input operand, the input is zero-extended.
        """
        self.__set_reg(self.__resolve_op(input0), output)
        return

    def __sex(self, input0, input1, output):
        """
        Functionally identical to STR in this implementation
        """
        self.__set_reg(self.__resolve_op(input0), output)
        return

    def __sub(self, input0, input1, output):
        """
        Subtracts the second input operand from the first input operand and writes the result to the output operand.
        The input operands can be literals and register values. The output operand must be a register.
        """
        self.__set_reg(self.__resolve_op(input0) - self.__resolve_op(input1), output)
        return

    def __undef(self, input0, input1, output):
        """
        Flags a register value as undefined. Not implemented.
        """
        pass

    def __unkn(self, input0, input1, output):
        """
        Untranslatable native instruction placeholder. Does nothing.
        """
        pass

    def __xor(self, input0, input1, output):
        """
        Binary XOR operation that connects the first two operands and stores the result in the third operand. 
        The input operands can be literals and register values. The output operand must be a register.
        """
        self.__set_reg(self.__resolve_op(input0) ^ self.__resolve_op(input1), output)
        return

    def __bisnz(self, input0, input1, output):
        """
        Sets a flag depending on whether another value is nonzero. The input operand can be a literal or 
        a register value. The output operand is a register.
        """
        # Assuming flag = 1 if nonzero
        self.__set_reg(0 if self.__resolve_op(input0) == 0 else 1, output)
        return

    def __equ(self, input0, input1, output):
        """
        Sets a flag depending on whether another two values are equal. The input operands can be literal or 
        register values. The output operand is a register.
        """
        # Assuming flag = 1 if equal
        self.__set_reg(
            1 if self.__resolve_op(input0) == self.__resolve_op(input1) else 0, output
        )
        return

    def __lshl(self, input0, input1, output):
        """
        Performs a logical left shift on a value. The two input operands can be either registers or literals 
        while the output operand must be a register.
        """
        try:
            self.__set_reg(
                self.__resolve_op(input0) << self.__resolve_op(input1), output
            )
        except ValueError:
            # Tried to do a negative bit shift, which is undefined behavior
            self.__set_reg(
                self.__resolve_op(input0) << abs(self.__resolve_op(input1)), output
            )
        except OverflowError:
            # Tried to do too big of a bit shift, so do alternate math
            self.__set_reg(
                self.__resolve_op(input0) * pow(2, self.__resolve_op(input1)), output
            )
        return

    def __lshr(self, input0, input1, output):
        """
        Performs a logical right shift on a value. The two input operands can be either registers or literals 
        while the output operand must be a register.
        """
        try:
            self.__set_reg(
                self.__resolve_op(input0) >> self.__resolve_op(input1), output
            )
        except ValueError:
            # Tried to do a negative bit shift, which is undefined behavior
            self.__set_reg(
                self.__resolve_op(input0) >> abs(self.__resolve_op(input1)), output
            )
        except OverflowError:
            # Tried to do too big of a bit shift, so do alternate math
            self.__set_reg(
                self.__resolve_op(input0) // pow(2, self.__resolve_op(input1)), output
            )
        return

    def __ashr(self, input0, input1, output):
        # TODO implement?
        self.__lshr(input0, input1, output)
        return

    #### END INSTRUCTION IMPLEMENTATION ####

    def execute(self, instruction):
        """
        Takes in a single REIL instruction and executes it in the approximate virtual machine
        """
        try:
            op = getattr(
                self, "_REILApproximateVM__" + _opcode_to_string(instruction.opcode)
            )
            op(instruction.input0, instruction.input1, instruction.output)
        except AttributeError as e:
            # TODO Add proper warning
            # print("Bad Instruction: " + str(instruction.opcode))
            pass
        return
