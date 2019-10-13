`timescale 1ns/1ps

module Memory(
    input wire clock,
    input wire[63:0] rd_addr,
    input wire[63:0] wr_addr,
    input wire[63:0] wr_data,
    input wire read,
    input wire write,
    output wire[63:0] rd_data,
    output wire has_error
  );

  reg[63:0] memory[0:127];

  assign has_error = (read && rd_addr > 1016) || (write && wr_addr > 1016) ||
                     (read && rd_addr[2:0]) || (write && wr_addr[2:0]);

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
    input wire[3:0] instr_len,
    input wire[63:0] new_ip,
    input wire set_ip,
    input wire[63:0] wr_mem_addr,
    input wire mem_write,
    output wire[3:0] instr_op,
    output wire[3:0] instr_func,
    output wire[3:0] instr_rega,
    output wire[3:0] instr_regb,
    output wire[71:0] instr_imm,
    output wire[63:0] next_ip,
    output wire[16:0] code_seek,
    output wire[4:0] cache_len
  );

  reg[7:0] cache[0:15];

  reg[3:0] base_pos;
  reg[4:0] free_size0;
  reg[4:0] free_size1;

  wire[3:0] base_pos0;
  wire[3:0] base_pos1;
  wire[3:0] base_pos2;
  wire[3:0] base_pos3;
  wire[3:0] base_pos4;
  wire[3:0] base_pos5;
  wire[3:0] base_pos6;
  wire[3:0] base_pos7;
  wire[3:0] base_pos8;
  wire[3:0] base_pos9;

  assign base_pos0 = base_pos;
  assign base_pos1 = base_pos + 1;
  assign base_pos2 = base_pos + 2;
  assign base_pos3 = base_pos + 3;
  assign base_pos4 = base_pos + 4;
  assign base_pos5 = base_pos + 5;
  assign base_pos6 = base_pos + 6;
  assign base_pos7 = base_pos + 7;
  assign base_pos8 = base_pos + 8;
  assign base_pos9 = base_pos + 9;

  assign instr_op = cache[base_pos0][7:4];
  assign instr_func = cache[base_pos0][3:0];
  assign instr_rega = cache[base_pos1][7:4];
  assign instr_regb = cache[base_pos1][3:0];

  assign instr_imm[7:0] = cache[base_pos1];
  assign instr_imm[15:8] = cache[base_pos2];
  assign instr_imm[23:16] = cache[base_pos3];
  assign instr_imm[31:24] = cache[base_pos4];
  assign instr_imm[39:32] = cache[base_pos5];
  assign instr_imm[47:40] = cache[base_pos6];
  assign instr_imm[55:48] = cache[base_pos7];
  assign instr_imm[63:56] = cache[base_pos8];
  assign instr_imm[71:64] = cache[base_pos9];

  reg[63:0] ip;

  wire[4:0] free_size;
  assign #1 free_size = clock ? free_size1 : free_size0;
  assign cache_len = (free_size ^ 15) + 1;
  assign next_ip = ip + instr_len;
  assign code_seek = ip + cache_len;

  wire refresh;
  assign refresh = mem_write && (wr_mem_addr | 7) >= next_ip && wr_mem_addr < code_seek;

  always @(negedge clock)
  begin
    free_size0 <= (reset || refresh || set_ip) ? 16 : (free_size + instr_len);
    ip <= reset ? 0 : (set_ip ? new_ip : next_ip);
    base_pos <= reset ? 0 : (base_pos + instr_len);
  end

  wire[4:0] avail_size = free_size + code_seek[2:0];
  wire[3:0] write_pos = base_pos + cache_len - code_seek[2:0];

  wire[3:0] write_pos0;
  wire[3:0] write_pos1;
  wire[3:0] write_pos2;
  wire[3:0] write_pos3;
  wire[3:0] write_pos4;
  wire[3:0] write_pos5;
  wire[3:0] write_pos6;
  wire[3:0] write_pos7;

  assign write_pos0 = write_pos;
  assign write_pos1 = write_pos + 1;
  assign write_pos2 = write_pos + 2;
  assign write_pos3 = write_pos + 3;
  assign write_pos4 = write_pos + 4;
  assign write_pos5 = write_pos + 5;
  assign write_pos6 = write_pos + 6;
  assign write_pos7 = write_pos + 7;

  always @(posedge clock)
  begin
    if (avail_size)
      cache[write_pos0] <= code_data[7:0];
    if (avail_size > 1)
      cache[write_pos1] <= code_data[15:8];
    if (avail_size > 2)
      cache[write_pos2] <= code_data[23:16];
    if (avail_size > 3)
      cache[write_pos3] <= code_data[31:24];
    if (avail_size > 4)
      cache[write_pos4] <= code_data[39:32];
    if (avail_size > 5)
      cache[write_pos5] <= code_data[47:40];
    if (avail_size > 6)
      cache[write_pos6] <= code_data[55:48];
    if (avail_size > 7)
      cache[write_pos7] <= code_data[63:56];

    free_size1 <= (avail_size <= 8) ? 0 : (avail_size - 8);

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
    input wire[63:0] next_ip,
    input wire[63:0] reg1_data,
    input wire[63:0] reg2_data,
    input wire[63:0] memx_data,
    input wire[63:0] arith_res,
    input wire[2:0] flags,
    input wire[16:0] code_seek,
    input wire mem_error,
    output wire[3:0] rd_reg1,
    output wire[3:0] rd_reg2,
    output wire[63:0] rd_memx_addr,
    output wire[3:0] wr_reg0,
    output wire[63:0] wr_memy_addr,
    output wire mem_read,
    output wire mem_write,
    output wire sp_add8,
    output wire[63:0] reg0_data,
    output wire[63:0] memy_data,
    output wire[1:0] arith_op,
    output wire[63:0] arith_x,
    output wire[63:0] arith_y,
    output wire arith_calc,
    output wire[63:0] new_ip,
    output wire set_ip,
    output wire[3:0] req_len,
    output wire[1:0] curr_status
  );

  reg[1:0] status;
  wire[1:0] new_status;
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

  wire[11:0] is_vaild;
  wire vaild;

  assign is_vaild[0] = func == 0;
  assign is_vaild[1] = func == 0;
  assign is_vaild[2] = func <= 6 && reg_b != 15 && reg_a != 15;
  assign is_vaild[3] = !func && reg_b != 15 && reg_a == 15;
  assign is_vaild[4] = !func && reg_b != 15 && reg_a != 15;
  assign is_vaild[5] = !func && reg_b != 15 && reg_a != 15;
  assign is_vaild[6] = func <= 3 && reg_b != 15 && reg_a != 15;
  assign is_vaild[7] = func <= 6;
  assign is_vaild[8] = func == 0;
  assign is_vaild[9] = func == 0;
  assign is_vaild[10] = !func && reg_a != 15 && reg_b == 15;
  assign is_vaild[11] = !func && reg_a != 15 && reg_b == 15;
  assign vaild = op > 11 ? 0 : is_vaild[op];

  wire[3:0] lengths[0:11];
  wire[3:0] length;
  wire exec;

  assign lengths[0] = 0;
  assign lengths[1] = 1;
  assign lengths[2] = 2;
  assign lengths[3] = 10;
  assign lengths[4] = 10;
  assign lengths[5] = 10;
  assign lengths[6] = 2;
  assign lengths[7] = 9;
  assign lengths[8] = 9;
  assign lengths[9] = 1;
  assign lengths[10] = 2;
  assign lengths[11] = 2;
  assign length = vaild ? lengths[op] : 0;
  assign exec = !reset && length <= instr_len && vaild && !status;

  wire[3:0] wr_regs[0:11];
  assign wr_regs[0] = 15;
  assign wr_regs[1] = 15;
  assign wr_regs[2] = cond_ok[func] ? reg_b : 15;
  assign wr_regs[3] = reg_b;
  assign wr_regs[4] = 15;
  assign wr_regs[5] = reg_a;
  assign wr_regs[6] = reg_b;
  assign wr_regs[7] = 15;
  assign wr_regs[8] = 4;
  assign wr_regs[9] = 15;
  assign wr_regs[10] = 4;
  assign wr_regs[11] = reg_a;

  assign rd_reg1 = reg_a;
  assign rd_reg2 = op >= 8 ? 4 : reg_b;
  assign wr_reg0 = !exec ? 15 : wr_regs[op];
  assign #1 rd_memx_addr = !clock ? (code_seek & ~7) : arith_res;
  assign wr_memy_addr = arith_res;
  assign mem_write = exec && (op == 4 || op == 8 || op == 10);
  assign #1 mem_read = !clock || (exec && (op == 5 || op == 9 || op == 11));
  assign sp_add8 = op == 9 || op == 11;
  assign reg0_data = (op == 5 || op == 11) ? memx_data : (op == 3 ? imm1 : arith_res);
  assign memy_data = op == 8 ? next_ip : reg1_data;
  assign arith_op = op == 6 ? func : 0;
  assign arith_x = (op == 6 ? reg1_data :
                    ((op == 4 || op == 5) ? imm1 : ((op == 10 || op == 8) ? -8 : 0)));
  assign arith_y = reg2_data;
  assign arith_calc = exec && op == 6;
  assign new_ip = op == 9 ? memx_data : imm2;
  assign set_ip = exec && ((op == 7 && cond_ok[func]) || op == 8 || op == 9);
  assign req_len = exec ? lengths[op] : 0;
  assign new_status = (reset || status) ? status : (!vaild ? 3 : (op == 0 ? 1 : 0));

  /*
  * Roughly, it is equivalent to the following code:
  *
  *   case (op)
  *   2:
  *   begin
  *     rd_reg1 = reg_a;
  *     wr_reg0 = cond_ok[func] ? reg_b : 15;
  *     reg0_data = reg1_data;
  *   end
  *   3:
  *   begin
  *     wr_reg0 = reg_b;
  *     reg0_data = imm1;
  *   end
  *   4:
  *   begin
  *     rd_reg1 = reg_a;
  *     rd_reg2 = reg_b;
  *     arith_x = imm1;
  *     arith_y = reg2_data;
  *     wr_memy_addr = arith_res;
  *     memy_data = reg1_data;
  *     mem_write = 1;
  *   end
  *   5:
  *   begin
  *     rd_reg2 = reg_b;
  *     arith_x = imm1;
  *     arith_y = reg2_data;
  *     rd_memx_addr = arith_res;
  *     wr_reg0 = reg_a;
  *     reg0_data = memx_data;
  *   end
  *   6:
  *   begin
  *     rd_reg1 = reg_a;
  *     rd_reg2 = reg_b;
  *     arith_op = func;
  *     arith_x = reg1_data;
  *     arith_y = reg2_data;
  *     wr_reg0 = reg_b;
  *     reg0_data = arith_res;
  *     arith_calc = 1;
  *   end
  *   7:
  *   begin
  *     set_ip = cond_ok[func];
  *     new_ip = imm2;
  *   end
  *   8:
  *   begin
  *     rd_reg2 = 4;
  *     wr_reg0 = 4;
  *     arith_x = -8;
  *     arith_y = reg2_data;
  *     reg0_data = arith_res;
  *     wr_memy_addr = arith_res;
  *     memy_data = next_ip;
  *     mem_write = 1;
  *     set_ip = 1;
  *     new_ip = imm2;
  *   end
  *   9:
  *   begin
  *     rd_reg2 = 4;
  *     arith_y = reg2_data;
  *     rd_memx_addr = arith_res;
  *     set_ip = 1;
  *     new_ip = memx_data;
  *     sp_add8 = 1;
  *   end
  *   10:
  *   begin
  *     rd_reg1 = reg_a;
  *     rd_reg2 = 4;
  *     wr_reg0 = 4;
  *     arith_x = -8;
  *     arith_y = reg2_data;
  *     reg0_data = arith_res;
  *     wr_memy_addr = arith_res;
  *     mem_write = 1;
  *     memy_data = reg1_data;
  *   end
  *   11:
  *   begin
  *     rd_reg2 = 4;
  *     arith_y = reg2_data;
  *     rd_memx_addr = arith_res;
  *     wr_reg0 = reg_a;
  *     reg0_data = memx_data;
  *     sp_add8 = 1;
  *   end
  *   endcase
  *
  */

  always @(posedge clock)
  begin
    #5;

    if (exec)
    begin
      $display("%0dns(posedge) InstructionDecoder: executing instruction op=%h func=%h",
              $stime, op, func);
    end
    else
    begin
      $display("%0dns(posedge) InstructionDecoder: waiting for instruction op=%h",
              $stime, op);
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

  wire[63:0] rd_memx_addr;
  wire[63:0] wr_memy_addr;
  wire[63:0] memx_data;
  wire[63:0] memy_data;
  wire mem_read;
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
  wire[63:0] next_ip;
  wire[63:0] new_ip;
  wire set_ip;

  Memory mem(clock, rd_memx_addr, wr_memy_addr, memy_data, mem_read, mem_write, memx_data,
              mem_error);

  RegisterFile regs(clock, wr_reg0, reg0_data, rd_reg1, rd_reg2, sp_add8, reg1_data, reg2_data);

  ArithmeticUnit au(clock, reset, arith_calc, arith_op, arith_x, arith_y, arith_res,
                    curr_flags);

  InstructionCache ic(clock, reset, memx_data, instr_req_len, new_ip, set_ip, wr_memy_addr,
                mem_write, instr_op, instr_func, instr_rega, instr_regb, instr_imm, next_ip,
                code_seek, instr_max_len);

  InstructionDecoder id(clock, reset, instr_op, instr_func, instr_rega, instr_regb, instr_imm,
              instr_max_len, next_ip, reg1_data, reg2_data, memx_data, arith_res, curr_flags,
              code_seek, mem_error, rd_reg1, rd_reg2, rd_memx_addr, wr_reg0, wr_memy_addr,
              mem_read, mem_write, sp_add8, reg0_data, memy_data, arith_op, arith_x, arith_y,
              arith_calc, new_ip, set_ip, instr_req_len, curr_status);

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
    clock = 1;
    #50;
    reset = 0;
    #50;
    while (!status)
    begin
      clock = !clock;
      #50;
    end
  end

endmodule
