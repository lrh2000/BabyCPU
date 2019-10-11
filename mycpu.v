`timescale 1ns/1ps

module Memory(
    input wire clock,
    input wire[63:0] rd_base,
    input wire[63:0] rd_offset,
    input wire[63:0] wr_base,
    input wire[63:0] wr_offset,
    input wire[63:0] wr_data,
    input wire write,
    output wire[63:0] wr_addr,
    output wire[63:0] rd_data,
    output wire has_error
  );

  reg[63:0] memory[0:127];

  wire[63:0] rd_addr;
  assign rd_addr = rd_base + rd_offset;
  assign wr_addr = wr_base + wr_offset;

  assign has_error = (rd_addr > 1016) || (wr_addr > 1016) || rd_addr[2:0] || wr_addr[2:0];

  assign rd_data = memory[rd_addr[9:3]];

  always @(negedge clock)
  begin
    if (write)
    begin
      memory[wr_addr[9:3]] = wr_data;
      $display("%0dns(negedge) Memory: write data %h into address %h", $stime, wr_data, wr_addr);
    end
  end

  initial
  begin
    $readmemh("memory_data.txt", memory);
  end

endmodule

module RegisterFile(
    input wire clock,
    input wire[3:0] wr_reg,
    input wire[63:0] wr_data,
    input wire[3:0] rd_reg1,
    input wire[3:0] rd_reg2,
    input wire sp_add8,
    output wire[63:0] rd_data1,
    output wire[63:0] rd_data2
  );

  reg[63:0] registers[0:15];

  assign rd_data1 = registers[rd_reg1];
  assign rd_data2 = registers[rd_reg2];

  always @(negedge clock)
  begin
    if (sp_add8)
    begin
      registers[4] <= registers[4] + 8;
      $display("%0dns(negedge) RegisterFile: write data %h into register 4",
                    $stime, registers[4] + 8);
    end

    registers[wr_reg] <= wr_data;
    if (wr_reg != 15)
      $display("%0dns(negedge) RegisterFile: write data %h into register %h",
                    $stime, wr_data, wr_reg);
  end

  initial
  begin
    $readmemh("reg_initial.txt", registers);
  end

endmodule

module ArithmeticUnit(
    input wire clock,
    input wire reset,
    input wire calc,
    input wire[1:0] op,
    input wire[63:0] x,
    input wire[63:0] y,
    output reg[63:0] res,
    output wire[2:0] curr_flags
  );

  reg[2:0] flags;
  assign curr_flags = flags;

  wire zf;
  wire sf;
  wire of;

  always @(*)
  begin
    case (op)
      0:
        res = y + x;
      1:
        res = y - x;
      2:
        res = y & x;
      3:
        res = y ^ x;
      default:
        res = 0;
    endcase
  end

  assign zf = res == 0;
  assign sf = res[63];
  assign of = (op == 0) ? ((x[63] ^ res[63]) & (y[63] ^ res[63])) :
          ((op == 1) ? ((x[63] ^ y[63]) & (y[63] ^ res[63])) : 0);

  always @(negedge clock)
  begin
    if (calc)
    begin
      flags[0] <= zf;
      flags[1] <= sf;
      flags[2] <= of;
      $display("%0dns(negedge) ArithmeticUnit: %h[op%h]%h=%h", $stime, y, op, x, res);
      $display("%0dns(negedge) ArithmeticUnit: flags [OF,SF,ZF]=[%h,%h,%h]", $stime, of, sf, zf);
    end
  end

endmodule

module InstructionCache(
    input wire clock,
    input wire reset,
    input wire[63:0] code_data,
    input wire[3:0] instr_req_len,
    input wire[63:0] new_ip,
    input wire set_ip,
    input wire[63:0] wr_mem_addr,
    input wire mem_write,
    output wire[3:0] instr_op,
    output wire[3:0] instr_func,
    output wire[3:0] instr_rega,
    output wire[3:0] instr_regb,
    output wire[71:0] instr_imm,
    output wire[63:0] curr_ip,
    output wire[16:0] code_seek,
    output wire[4:0] instr_max_len
  );

  reg[7:0] cache[0:15];

  assign instr_op = cache[0][7:4];
  assign instr_func = cache[0][3:0];
  assign instr_rega = cache[1][7:4];
  assign instr_regb = cache[1][3:0];

  assign instr_imm[7:0] = cache[1];
  assign instr_imm[15:8] = cache[2];
  assign instr_imm[23:16] = cache[3];
  assign instr_imm[31:24] = cache[4];
  assign instr_imm[39:32] = cache[5];
  assign instr_imm[47:40] = cache[6];
  assign instr_imm[55:48] = cache[7];
  assign instr_imm[63:56] = cache[8];
  assign instr_imm[71:64] = cache[9];

  reg[4:0] len;
  reg[63:0] ip;

  assign instr_max_len = len;
  assign curr_ip = ip;
  assign code_seek = ip + len;

  always @(negedge clock)
  begin
    if (1 >= instr_req_len)
      cache[1 - instr_req_len] <= cache[1];
    if (2 >= instr_req_len)
    begin
      cache[2 - instr_req_len] <= cache[2];
      cache[3 - instr_req_len] <= cache[3];
      cache[4 - instr_req_len] <= cache[4];
      cache[5 - instr_req_len] <= cache[5];
      cache[6 - instr_req_len] <= cache[6];
      cache[7 - instr_req_len] <= cache[7];
      cache[8 - instr_req_len] <= cache[8];
    end
    if (9 >= instr_req_len)
      cache[9 - instr_req_len] <= cache[9];
    cache[10 - instr_req_len] <= cache[10];
    cache[11 - instr_req_len] <= cache[11];
    cache[12 - instr_req_len] <= cache[12];
    cache[13 - instr_req_len] <= cache[13];
    cache[14 - instr_req_len] <= cache[14];
    cache[15 - instr_req_len] <= cache[15];

    len <= ((mem_write && wr_mem_addr + 7 >= ip + instr_req_len &&
          wr_mem_addr < ip + len) || reset || set_ip) ? 0 : (len - instr_req_len);
    ip <= reset ? 0 : (set_ip ? new_ip : (ip + instr_req_len));
  end

  always @(posedge clock)
  begin
    if (code_seek[2:0] == 0 && len <= 15)
      cache[len] <= code_data[7:0];
    if (code_seek[2:0] <= 1 && len + 1 - code_seek[2:0] <= 15)
      cache[len + 1 - code_seek[2:0]] <= code_data[15:8];
    if (code_seek[2:0] <= 2 && len + 2 - code_seek[2:0] <= 15)
      cache[len + 2 - code_seek[2:0]] <= code_data[23:16];
    if (code_seek[2:0] <= 3 && len + 3 - code_seek[2:0] <= 15)
      cache[len + 3 - code_seek[2:0]] <= code_data[31:24];
    if (code_seek[2:0] <= 4 && len + 4 - code_seek[2:0] <= 15)
      cache[len + 4 - code_seek[2:0]] <= code_data[39:32];
    if (code_seek[2:0] <= 5 && len + 5 - code_seek[2:0] <= 15)
      cache[len + 5 - code_seek[2:0]] <= code_data[47:40];
    if (code_seek[2:0] <= 6 && len + 6 - code_seek[2:0] <= 15)
      cache[len + 6 - code_seek[2:0]] <= code_data[55:48];
    if (len + 7 - code_seek[2:0] <= 15)
      cache[len + 7 - code_seek[2:0]] <= code_data[63:56];

    len <= (len + 8 - code_seek[2:0] >= 16) ? 16 : (len + 8 - code_seek[2:0]);

    $display("%0dns(posedge) InstructionCache: current ip=%h", $stime, ip);
  end

endmodule

module InstructionDecoder(
    input wire clock,
    input wire reset,
    input wire[3:0] op,
    input wire[3:0] func,
    input wire[3:0] reg_a,
    input wire[3:0] reg_b,
    input wire[71:0] imm,
    input wire[4:0] instr_len,
    input wire[63:0] curr_ip,
    input wire[63:0] reg1_data,
    input wire[63:0] reg2_data,
    input wire[63:0] memx_data,
    input wire[63:0] arith_res,
    input wire[2:0] flags,
    input wire[16:0] code_seek,
    input wire mem_error,
    output reg[3:0] rd_reg1,
    output reg[3:0] rd_reg2,
    output reg[63:0] rd_memx_base,
    output reg[63:0] rd_memx_offs,
    output reg[3:0] wr_reg0,
    output reg[63:0] wr_memy_base,
    output reg[63:0] wr_memy_offs,
    output reg mem_write,
    output reg sp_add8,
    output reg[63:0] reg0_data,
    output reg[63:0] memy_data,
    output reg[1:0] arith_op,
    output reg[63:0] arith_x,
    output reg[63:0] arith_y,
    output reg arith_calc,
    output reg[63:0] new_ip,
    output reg set_ip,
    output reg[3:0] req_len,
    output wire[1:0] curr_status
  );

  reg[1:0] status;
  reg[1:0] new_status;
  assign curr_status = status;

  wire[6:0] cond_ok;
  assign cond_ok[0] = 1;
  assign cond_ok[1] = (flags[1] ^ flags[2]) | flags[0];
  assign cond_ok[2] = flags[1] ^ flags[2];
  assign cond_ok[3] = flags[0];
  assign cond_ok[4] = ~flags[0];
  assign cond_ok[5] = ~(flags[1] ^ flags[2]);
  assign cond_ok[6] = ~(flags[1] ^ flags[2]) & ~flags[0];

  wire[63:0] imm1;
  wire[63:0] imm2;
  assign imm1 = imm[71:8];
  assign imm2 = imm[63:0];

  always @(*)
  begin
    #1;

    rd_reg1 = 0;
    rd_reg2 = 0;
    rd_memx_base = 0;
    rd_memx_offs = 0;
    wr_reg0 = 15;
    wr_memy_base = 0;
    wr_memy_offs = 0;
    mem_write = 0;
    sp_add8 = 0;
    reg0_data = 0;
    memy_data = 0;
    arith_op = 0;
    arith_x = 0;
    arith_y = 0;
    arith_calc = 0;
    new_ip = 0;
    set_ip = 0;
    req_len = 0;
    new_status = status;

    if (!status && clock)
    begin
      case (op)
        0:  req_len = 0;
        1:  req_len = 1;
        2:  req_len = 2;
        3:  req_len = 10;
        4:  req_len = 10;
        5:  req_len = 10;
        6:  req_len = 2;
        7:  req_len = 9;
        8:  req_len = 10;
        9:  req_len = 1;
        10: req_len = 2;
        11: req_len = 2;
        default: req_len = 0;
      endcase

      if (req_len <= instr_len)
      begin
        case (op)
        0:
          new_status = func ? 3 : 1;
        1:
          new_status = func ? 3 : 0;
        2:
          new_status = (func <= 6 && reg_b != 15 && reg_a != 15) ? 0 : 3;
        3:
          new_status = (!func && reg_b != 15 && reg_a == 15) ? 0 : 3;
        4:
          new_status = (!func && reg_b != 15 && reg_a != 15) ? 0 : 3;
        5:
          new_status = (!func && reg_b != 15 && reg_a != 15) ? 0 : 3;
        6:
          new_status = (func <= 3 && reg_b != 15 && reg_a != 15) ? 0 : 3;
        7:
          new_status = (func <= 6) ? 0 : 3;
        8:
          new_status = func ? 3 : 0;
        9:
          new_status = func ? 3 : 0;
        10:
          new_status = (!func && reg_a != 15 && reg_b == 15) ? 0 : 3;
        11:
          new_status = (!func && reg_a != 15 && reg_b == 15) ? 0 : 3;
        default:
          new_status = 3;
        endcase

        if (!new_status)
        begin
          case (op)
          2:
          begin
            rd_reg1 = reg_a;
            wr_reg0 = cond_ok[func] ? reg_b : 15;
            reg0_data = reg1_data;
          end
          3:
          begin
            wr_reg0 = reg_b;
            reg0_data = imm1;
          end
          4:
          begin
            rd_reg1 = reg_a;
            rd_reg2 = reg_b;
            wr_memy_base = reg2_data;
            wr_memy_offs = imm1;
            memy_data = reg1_data;
            mem_write = 1;
          end
          5:
          begin
            rd_reg2 = reg_b;
            rd_memx_base = reg2_data;
            rd_memx_offs = imm1;
            wr_reg0 = reg_a;
            reg0_data = memx_data;
          end
          6:
          begin
            rd_reg1 = reg_a;
            rd_reg2 = reg_b;
            arith_op = func;
            arith_x = reg1_data;
            arith_y = reg2_data;
            wr_reg0 = reg_b;
            reg0_data = arith_res;
            arith_calc = 1;
          end
          7:
          begin
            set_ip = cond_ok[func];
            new_ip = imm2;
          end
          8:
          begin
            rd_reg2 = 4;
            wr_reg0 = 4;
            reg0_data = reg2_data - 8;
            wr_memy_base = reg2_data - 8;
            memy_data = curr_ip + 9;
            mem_write = 1;
            set_ip = 1;
            new_ip = imm2;
          end
          9:
          begin
            rd_reg2 = 4;
            rd_memx_base = reg2_data;
            set_ip = 1;
            new_ip = memx_data;
            sp_add8 = 1;
          end
          10:
          begin
            rd_reg1 = reg_a;
            rd_reg2 = 4;
            wr_reg0 = 4;
            reg0_data = reg2_data - 8;
            wr_memy_base = reg2_data - 8;
            mem_write = 1;
            memy_data = reg1_data;
          end
          11:
          begin
            rd_reg2 = 4;
            rd_memx_base = reg2_data;
            wr_reg0 = reg_a;
            reg0_data = memx_data;
            sp_add8 = 1;
          end
          default: ;
          endcase
        end
        $display("%0dns(clk %h) InstructionDecoder: executing instruction op=%h func=%h",
                  $stime, clock, op, func);
      end
      else
      begin
        $display("%0dns(clk %h) InstructionDecoder: waiting for instruction op=%h",
                  $stime, clock, op);
        req_len = 0;
      end
    end

    if (!clock)
    begin
      rd_memx_base[16:3] = code_seek[16:3];
    end
  end

  always @(negedge clock)
  begin
    status <= reset ? 0 : (mem_error ? 2 : new_status);
  end

  always @(posedge clock)
  begin
    status <= mem_error ? 2 : status;
  end

  always @(status)
  begin
    if (status)
      $display("%0dns(clk %h) InstructionDecoder: non-zero status %h", $stime, clock, status);
  end

endmodule


module MyCPU(
    input wire clock,
    input wire reset,
    output wire[1:0] status
  );

  wire[3:0] rd_reg1;
  wire[3:0] rd_reg2;
  wire[3:0] wr_reg0;
  wire[63:0] reg1_data;
  wire[63:0] reg2_data;
  wire[63:0] reg0_data;
  wire sp_add8;

  wire[1:0] arith_op;
  wire[63:0] arith_x;
  wire[63:0] arith_y;
  wire[63:0] arith_res;
  wire arith_calc;

  wire[63:0] rd_memx_base;
  wire[63:0] rd_memx_offs;
  wire[63:0] wr_memy_base;
  wire[63:0] wr_memy_offs;
  wire[63:0] memx_data;
  wire[63:0] memy_data;
  wire[63:0] wr_mem_addr;
  wire mem_write;
  wire mem_error;

  wire[3:0] instr_op;
  wire[3:0] instr_func;
  wire[3:0] instr_rega;
  wire[3:0] instr_regb;
  wire[71:0] instr_imm;
  wire[4:0] instr_max_len;

  wire[16:0] code_seek;
  wire[3:0] instr_req_len;
  wire[1:0] curr_status;
  wire[2:0] curr_flags;
  wire[63:0] curr_ip;
  wire[63:0] new_ip;
  wire set_ip;

  Memory mem(clock, rd_memx_base, rd_memx_offs, wr_memy_base, wr_memy_offs, memy_data,
              mem_write, wr_mem_addr, memx_data, mem_error);

  RegisterFile regs(clock, wr_reg0, reg0_data, rd_reg1, rd_reg2, sp_add8, reg1_data, reg2_data);

  ArithmeticUnit au(clock, reset, arith_calc, arith_op, arith_x, arith_y, arith_res,
                    curr_flags);

  InstructionCache ic(clock, reset, memx_data, instr_req_len, new_ip, set_ip, wr_mem_addr,
                mem_write, instr_op, instr_func, instr_rega, instr_regb, instr_imm, curr_ip,
                code_seek, instr_max_len);

  InstructionDecoder id(clock, reset, instr_op, instr_func, instr_rega, instr_regb, instr_imm,
              instr_max_len, curr_ip, reg1_data, reg2_data, memx_data, arith_res, curr_flags,
              code_seek, mem_error, rd_reg1, rd_reg2, rd_memx_base, rd_memx_offs, wr_reg0,
              wr_memy_base, wr_memy_offs, mem_write, sp_add8, reg0_data, memy_data, arith_op,
              arith_x, arith_y, arith_calc, new_ip, set_ip, instr_req_len, curr_status);

  assign status = curr_status;

endmodule

module TestCPU();

  reg clock;
  reg reset;
  wire[1:0] status;

  MyCPU cpu(clock, reset, status);

  initial
  begin
    #50;
    reset = 1;
    #50;
    clock = 1;
    #50;
    clock = 0;
    #50;
    reset = 0;
    #50;
    clock = 1;
    #50;
    while (!status)
    begin
      clock = !clock;
      #50;
    end
  end

endmodule
