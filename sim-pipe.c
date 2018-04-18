#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/* An implementation of 5-stage classic pipeline simulation */

/* don't count instructions flag, enabled by default, disable for inst count */
#undef NO_INSN_COUNT

#include "host.h"
#include "misc.h"
#include "machine.h"
#include "regs.h"
#include "memory.h"
#include "loader.h"
#include "syscall.h"
#include "dlite.h"
#include "sim.h"
#include "sim-pipe.h"
#include "ptrace.h"

/* simulated registers */
static struct regs_t regs;

/* simulated memory */
static struct mem_t *mem = NULL;

/* register simulator-specific options */
void
sim_reg_options(struct opt_odb_t *odb)
{
  opt_reg_header(odb, 
"sim-pipe: This simulator implements based on sim-fast.\n"
		 );
}

/* check simulator-specific option values */
void
sim_check_options(struct opt_odb_t *odb, int argc, char **argv)
{
  if (dlite_active)
    fatal("sim-pipe does not support DLite debugging");
}

/* register simulator-specific statistics */
void
sim_reg_stats(struct stat_sdb_t *sdb)
{
#ifndef NO_INSN_COUNT
  stat_reg_counter(sdb, "sim_num_insn",
		   "total number of instructions executed",
		   &sim_num_insn, sim_num_insn, NULL);
#endif /* !NO_INSN_COUNT */
  stat_reg_int(sdb, "sim_elapsed_time",
	       "total simulation time in seconds",
	       &sim_elapsed_time, 0, NULL);
#ifndef NO_INSN_COUNT
  stat_reg_formula(sdb, "sim_inst_rate",
		   "simulation speed (in insts/sec)",
		   "sim_num_insn / sim_elapsed_time", NULL);
#endif /* !NO_INSN_COUNT */
  ld_reg_stats(sdb);
  mem_reg_stats(mem, sdb);
}


struct ifid_buf fd;
struct idex_buf de;
struct exmem_buf em;
struct memwb_buf mw;

#define DNA			(-1)

/* general register dependence decoders */
#define DGPR(N)			(N)
#define DGPR_D(N)		((N) &~1)

/* floating point register dependence decoders */
#define DFPR_L(N)		(((N)+32)&~1)
#define DFPR_F(N)		(((N)+32)&~1)
#define DFPR_D(N)		(((N)+32)&~1)

/* miscellaneous register dependence decoders */
#define DHI			(0+32+32)
#define DLO			(1+32+32)
#define DFCC		(2+32+32)
#define DTMP		(3+32+32)

/* initialize the simulator */
void
sim_init(void)
{
  /* allocate and initialize register file */
  regs_init(&regs);

  /* allocate and initialize memory space */
  mem = mem_create("mem");
  mem_init(mem);

  /* initialize stage latches*/
 
  /* IF/ID */

  /* ID/EX */
  de.latched = 0;
  /* EX/MEM */

  /* MEM/WB */

}

/* load program into simulated state */
void
sim_load_prog(char *fname,		/* program to load */
	      int argc, char **argv,	/* program arguments */
	      char **envp)		/* program environment */
{
  /* load program text and data, set up environment, memory, and regs */
  ld_load_prog(fname, argc, argv, envp, &regs, mem, TRUE);
}

/* print simulator-specific configuration information */
void
sim_aux_config(FILE *stream)
{  
	/* nothing currently */
}

/* dump simulator-specific auxiliary simulator statistics */
void
sim_aux_stats(FILE *stream)
{  /* nada */}

/* un-initialize simulator-specific state */
void 
sim_uninit(void)
{ /* nada */ }


/*
 * configure the execution engine
 */

/* next program counter */
#define SET_NPC(EXPR)		(regs.regs_NPC = (EXPR))

/* current program counter */
#define CPC			(regs.regs_PC)

/* general purpose registers */
#define GPR(N)			(regs.regs_R[N])
#define SET_GPR(N,EXPR)		(regs.regs_R[N] = (EXPR))
#define DECLARE_FAULT(EXP) 	{;}
#if defined(TARGET_PISA)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_L(N)		(regs.regs_F.l[(N)])
#define SET_FPR_L(N,EXPR)	(regs.regs_F.l[(N)] = (EXPR))
#define FPR_F(N)		(regs.regs_F.f[(N)])
#define SET_FPR_F(N,EXPR)	(regs.regs_F.f[(N)] = (EXPR))
#define FPR_D(N)		(regs.regs_F.d[(N) >> 1])
#define SET_FPR_D(N,EXPR)	(regs.regs_F.d[(N) >> 1] = (EXPR))

/* miscellaneous register accessors */
#define SET_HI(EXPR)		(regs.regs_C.hi = (EXPR))
#define HI			(regs.regs_C.hi)
#define SET_LO(EXPR)		(regs.regs_C.lo = (EXPR))
#define LO			(regs.regs_C.lo)
#define FCC			(regs.regs_C.fcc)
#define SET_FCC(EXPR)		(regs.regs_C.fcc = (EXPR))

#endif

/* precise architected memory state accessor macros */
#define READ_BYTE(SRC, FAULT)						\
  ((FAULT) = md_fault_none, MEM_READ_BYTE(mem, (SRC)))
#define READ_HALF(SRC, FAULT)						\
  ((FAULT) = md_fault_none, MEM_READ_HALF(mem, (SRC)))
#define READ_WORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, MEM_READ_WORD(mem, (SRC)))
#ifdef HOST_HAS_QWORD
#define READ_QWORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, MEM_READ_QWORD(mem, (SRC)))
#endif /* HOST_HAS_QWORD */

#define WRITE_BYTE(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, MEM_WRITE_BYTE(mem, (DST), (SRC)))
#define WRITE_HALF(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, MEM_WRITE_HALF(mem, (DST), (SRC)))
#define WRITE_WORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, MEM_WRITE_WORD(mem, (DST), (SRC)))
#ifdef HOST_HAS_QWORD
#define WRITE_QWORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, MEM_WRITE_QWORD(mem, (DST), (SRC)))
#endif /* HOST_HAS_QWORD */

/* system call handler macro */
#define SYSCALL(INST)	sys_syscall(&regs, mem_access, mem, INST, TRUE)

#ifndef NO_INSN_COUNT
#define INC_INSN_CTR()	sim_num_insn++
#else /* !NO_INSN_COUNT */
#define INC_INSN_CTR()	/* nada */
#endif /* NO_INSN_COUNT */


/* start simulation, program loaded, processor precise state initialized */
void
sim_main(void)
{
  fprintf(stderr, "sim: ** starting *pipe* functional simulation **\n");

  /* must have natural byte/word ordering */
  if (sim_swap_bytes || sim_swap_words)
    fatal("sim: *pipe* functional simulation cannot swap bytes or words");

  /* set up initial default next PC */
  regs.regs_NPC = regs.regs_PC + sizeof(md_inst_t);
  /* maintain $r0 semantics */
  regs.regs_R[MD_REG_ZERO] = 0;

  // must inital the fd.PC
  //fd.PC = regs.regs_PC;

 int cycle_count = 0;
  while (TRUE)
  {
    fprintf(stderr, "\n[Cycle %d]--------------------------",  cycle_count);
    /*start your pipeline simulation here*/

    md_inst_t instruction;
    if(de.latched == 1){
      // make the NPC and PC unchanged.
    }else{
      regs.regs_NPC = regs.regs_PC + sizeof(md_inst_t);
    }
    regs.regs_PC = regs.regs_NPC;
    MD_FETCH_INSTI(instruction, mem, regs.regs_PC);

    fprintf(stderr, "\n[IF]   ");
    md_print_insn(instruction,  regs.regs_PC,  stderr);  
    fprintf(stderr, "\n[ID]  ");
    md_print_insn(fd.inst,  fd.PC,  stderr);
    fprintf(stderr, "\n[EXE] ");
    md_print_insn(de.inst,  de.PC,  stderr); 
    fprintf(stderr, "\n[MEM] ");
    md_print_insn(em.inst,  em.PC,  stderr);    
    fprintf(stderr, "\n[WB] ");
    md_print_insn(mw.inst,  mw.PC,  stderr);
    //fprintf(stderr, "\nde.latched %d ",de.latched);

    do_wb();do_mem();do_ex();do_id();do_if();

    fprintf(stderr, "\n[REGS]");
    md_print_ireg(regs.regs_R, 2,stderr);
    md_print_ireg(regs.regs_R, 3,stderr);
    md_print_ireg(regs.regs_R, 4,stderr);
    md_print_ireg(regs.regs_R, 5,stderr);
    md_print_ireg(regs.regs_R, 6,stderr);
    //md_print_iregs(regs.regs_R,stderr);


    enum md_fault_type _fault; 
    fprintf(stderr, " mem=%d", READ_WORD(16+GPR(30),  _fault));
    cycle_count++;
    
    //fprintf(stderr, "\ncycle 15, value1 %d\n", de.oprand.value1 );

  }
}

void do_if()
{
  if(em.needJump == 1){
    //fprintf(stderr, "\nI need Jump to %x \n",em.aluOutput);
    regs.regs_PC = em.aluOutput;
    em.needJump =0;
    
  }
  if(em.needJump != 1 && de.latched == 1){
    return; // not pass anything to fd
  }

  md_inst_t instruction;
  MD_FETCH_INSTI(instruction, mem, regs.regs_PC);
  fd.PC = regs.regs_PC;
  fd.inst = instruction;
}

void do_id()
{
  if(em.needJump == 1){
    de.inst = MD_NOP_INST;
    de.opcode = NOP;
    de.latched = 0;
    return;
  }
  de.inst = fd.inst;
  de.PC = fd.PC;
  de.latched = 0;
  /*decode ins, detect data/control hazard, read reg for oprands*/
  MD_SET_OPCODE(de.opcode, de.inst);
  md_inst_t inst= de.inst;
#define DEFINST(OP,MSK,NAME,OPFORM,RES,FLAGS,O1,O2,I1,I2,I3)\
  if (OP==de.opcode){\
    de.instFlags = FLAGS;\
    de.oprand.out1 = O1;\
    de.oprand.out2 = O2;\
    de.oprand.in1 = I1;\
    de.oprand.in2 = I2;\
    de.oprand.in3 = I3;\
    goto READ_OPRAND_VALUE;\
  }
#define DEFLINK(OP,MSK,NAME,MASK,SHIFT)
#define CONNECT(OP)
#include "machine.def"
  
  // read reg for operands
READ_OPRAND_VALUE: 
    
    switch(de.opcode){
      
      case ADDIU:
      case ANDI:
      case SLL:
      case SLTI:
        de.oprand.value1 = GPR(de.oprand.in1);
        de.oprand.imm = IMMI(de.inst);
        break;
      case LW:
        de.oprand.value2 = GPR(de.oprand.in2);
        de.oprand.imm = IMMI(de.inst);
        break;
      case ADDU:
      case ADD:
        de.oprand.value1 = GPR(de.oprand.in1);
        de.oprand.value2 = GPR(de.oprand.in2);
        break;
      case SW://sll     $5,$4,2
        de.oprand.value1 = GPR(de.oprand.in1);
        de.oprand.value2 = GPR(de.oprand.in2);
        de.oprand.imm = IMMI(de.inst);
        break;
     
      case BNE:
        de.oprand.value1 = GPR(de.oprand.in1);
        de.oprand.value2 = GPR(de.oprand.in2);
        de.oprand.immaddr = TARGI(de.inst);// jump addr
        break;
      case JUMP:
        de.oprand.immaddr = TARGI(de.inst);// jump addr
        break;
      
      default:
        break;
	
    }
    // fprintf(stderr, "\nin1 %d ",de.oprand.in1);
    // fprintf(stderr, "\nin2 %d ",de.oprand.in2);
    // fprintf(stderr, "\nin3 %d ",de.oprand.in3);
    // fprintf(stderr, "\nout1 %d ",de.oprand.out1);
    // fprintf(stderr, "\nout2 %d ",de.oprand.out2);

    /*detect data hazard: the unassigned regs are -1 
      NOP = 1
    */
    /*since we handle each stage in the reversed order, no need to check mw*/
    // fprintf(stderr, "\nde.oprand.in2: %d\n", de.oprand.in2 );
    // fprintf(stderr, "\nde.oprand.in1: %d\n", de.oprand.in1 );
    // fprintf(stderr, "\nde.oprand.value1: %d\n", de.oprand.value1 );
    // fprintf(stderr, "\nde.oprand.value2: %d\n", de.oprand.value2 );
    // fprintf(stderr, "\nmw.oprand.out1: %d\n", mw.oprand.out1 );
    if(de.oprand.in1 != -1 && de.opcode > 1 ){ // in1 is needed
      if(de.oprand.in1 == em.oprand.out1 && em.opcode > 1){ // same with em out1
        de.latched = 1; // stalled
        de.inst = MD_NOP_INST;
        de.opcode = NOP;
        
        
      }
      if(mw.opcode > 1 && de.oprand.in1 == mw.oprand.out1){
        
          de.latched = 1; // stalled
        de.inst = MD_NOP_INST;
        de.opcode = NOP;
        
      }
    }
    if(de.oprand.in2 != -1 && de.opcode > 0){
      if(de.oprand.in2 == em.oprand.out1 && em.opcode > 1){
        
          de.latched = 1; // stalled
          de.inst = MD_NOP_INST;
          de.opcode = NOP;
        
      }
      if(mw.opcode > 1 && de.oprand.in2 == mw.oprand.out1){
        de.latched = 1; // stalled
        de.inst = MD_NOP_INST;
        de.opcode = NOP;
      }
    }
}

void do_ex()
{
  if(em.needJump == 1){
    em.inst = MD_NOP_INST;
    em.opcode = NOP;
    return;
  }
  /*compute ALU and mem addr for load and store inst, and relove branch*/
  em.inst = de.inst;
  em.PC = de.PC;
  em.opcode = de.opcode;
  em.oprand = de.oprand;
  em.needJump = 0;
  
  md_inst_t inst= em.inst;

  switch (de.opcode)
  {
#define DEFINST(OP,MSK,NAME,OPFORM,RES,FLAGS,O1,O2,I1,I2,I3)   \
  case OP:              \
    SYMCAT(OP,_IMPL);           \
    break;
#define DEFLINK(OP,MSK,NAME,MASK,SHIFT)
#define CONNECT(OP)
#define DECLARE_FAULT(FAULT)            \
    { /* uncaught... */break; }
#include "machine.def"
    default:
    break;
  }
  //fprintf(stderr, "after ex, em opcode is %d\n", em.opcode);
}

void do_mem()
{
  
  

  md_inst_t  inst= mw.inst;
  enum md_fault_type _fault; 
  
  switch (em.opcode)
  {
    case SW:
      WRITE_WORD((word_t)GPR(em.oprand.in1), em.aluOutput, _fault);
      if (_fault != md_fault_none)          
        DECLARE_FAULT(_fault);
      break;
    case LW:
      mw.memload = READ_WORD(em.aluOutput, _fault); // buffer the load result
      //fprintf(stderr, "\nmemload is %d\n", mw.memload);
      if (_fault != md_fault_none)          
        DECLARE_FAULT(_fault);
      break;
  }
  mw.inst = em.inst;
  mw.PC = em.PC;
  mw.opcode = em.opcode;
  mw.oprand = em.oprand;
  mw.alui = em.alui;
  mw.aluf = em.aluf;  
  //fprintf(stderr, "\nafter mem, mw opcode is %d\n", mw.opcode);
}                                                                                        

void do_wb()
{
  md_inst_t inst= mw.inst;
  switch (mw.opcode)
  {
    case ADDU:
    case ADD:
    case ADDIU:
    case SLTI:
    case SLL:
    case ANDI:
      // fprintf(stderr, "set reg with alui %x\n", mw.alui);
      // fprintf(stderr, "set reg into out1 %d\n", mw.oprand.out1);
      SET_GPR(mw.oprand.out1,mw.alui);
      //fprintf(stderr, "reg  out1 is %d\n", GPR(mw.oprand.out1));
      break;
    case SW:
      break;
    case LW:
      SET_GPR(mw.oprand.out1, mw.memload);
      break;
    case SYSCALL:
       SYSCALL(inst);
       break;
  }

}

