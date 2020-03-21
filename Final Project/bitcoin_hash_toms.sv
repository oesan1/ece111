module bitcoin_hash(input logic clk, reset_n, start,
	input logic [15:0] message_addr, output_addr,
	output logic done, mem_clk, mem_we,
	output logic [15:0] mem_addr,
	output logic [31:0] mem_write_data,
	input logic [31:0] mem_read_data);

	assign mem_clk = clk;
	logic	  [31:0] temp[32];                  // Holds original msg read from memory
	logic   [31:0] w[64];
	logic   [31:0] s1, s0;
	logic   [31:0] a, b, c, d, e, f, g, h;
	logic   [15:0] count = 0;
	logic   [15:0] msg_size = 19;
	logic   [31:0] value;
	logic	  [3:0]  msg_num;               // Keeps track of which block is hashed, check against msg_total
	logic   [3:0]  msg_total = 2;             // Total num of blocks being hashed
	int     nonceCount = 0;
	int     totalNonce = 16;
	int     isPhase3 = 0;
	logic	  [31:0] prehash_add[64];

	//logic   [31:0] first = 0;
	
	// SHA256 K constants
	parameter int sha256_k[0:63] = '{
		32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
		32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
		32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
		32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
		32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
		32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
		32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
		32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
	};
	logic [31:0]  h0 = 32'h6a09e667,	// Store in between phases hash values
					  h1 = 32'hbb67ae85,
					  h2 = 32'h3c6ef372,
					  h3 = 32'ha54ff53a,
					  h4 = 32'h510e527f,
					  h5 = 32'h9b05688c,
					  h6 = 32'h1f83d9ab,
					  h7 = 32'h5be0cd19;
					  
	logic [31:0]  f0 = 32'h6a09e667,	// Initial hash values, should not change
					  f1 = 32'hbb67ae85,
					  f2 = 32'h3c6ef372,
					  f3 = 32'ha54ff53a,
					  f4 = 32'h510e527f,
					  f5 = 32'h9b05688c,
					  f6 = 32'h1f83d9ab,
					  f7 = 32'h5be0cd19;
					  
	logic [31:0] b10, b11, b12, b13, b14, b15, b16, b17;		// first block's hash

	
	// right rotation
	function logic [31:0] rightrotate(input logic [31:0] x,
		input logic [ 7:0] r);
		rightrotate = (x >> r) | (x << (32-r));
	endfunction
	
	// K + W Addition (pipelining)
	function void sha256_add(input logic [31:0] w, input logic [7:0] t);
		//if (t < 63) begin
			prehash_add[t] = sha256_k[t] + w;
		//end else begin
		//	sha256_add = sha256_k[0] + w;
		//end
	endfunction
	
	/*
	function logic [31:0] sha256_add(input logic [31:0] w, input logic [7:0] t);
		//if (t < 63) begin
			prehash_add[t] = sha256_k[t] + w;
		//end else begin
		//	sha256_add = sha256_k[0] + w;
		//end
	endfunction
	*/
	
	// SHA256 hash round
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, prehash_add,
												input logic [7:0] t);
		logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
		begin
			 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
			 ch = (e & f) ^ ((~e) & g);
			 t1 = h + S1 + ch + prehash_add;
			 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
			 maj = (a & b) ^ (a & c) ^ (b & c);
			 t2 = S0 + maj;

			 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
		end
	endfunction
	
	// Pads original message stored in temp with 1, zeros, and msg size
	function void padding();		// change to void later just to see
		logic [31:0] m;
		temp[19] = nonceCount;
		//$display("Inside padding funct, temp[19] = %x", temp[19]);

		begin
			temp[20] = 32'h80000000;
			for (m = 21; m < 31; m++) begin
				  temp[m] = 32'h00000000;	
			end
			temp[31] = 32'd640; 
			
		end
	endfunction
	/*
	
	function void print_h();
		$display("print h");
		$display("%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x", h0, h1, h2, h3, h4, h5, h6, h7);
	endfunction
	
	function void print_abc();
		$display("print abc");
		$display("%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x", a, b, c, d, e, f, g, h);
	endfunction
	*/
	function void word_exp(input logic [3:0] msg_num);
		logic [31:0] t;
		logic [31:0] sub_temp[16];
		temp[19] = nonceCount;
		//$display("Inside word exp, temp[19] = %x, msg_num = %d", temp[19], msg_num);
		if(msg_num < 1) begin
			sub_temp = temp[0:15];
			//$display("First block:");
		end else begin
			//$display("Second block:");
			sub_temp = temp[16:31];
		end
		
		
		// print sub_temp
		
		//$display("Printing block");
		 /*for (t = 0; t < 16; t++) begin
			$display("\tmessage[%d] = %x", t, sub_temp[t]);
		 end
		 */
		 
		
		
		begin
			for (t = 0; t < 64; t++) begin
			  if (t < 16) begin
					w[t] = sub_temp[t];
			  end else begin
					s0 = rightrotate(w[t-15], 7) ^ rightrotate(w[t-15], 18) ^ (w[t-15] >> 3);
					s1 = rightrotate(w[t-2], 17) ^ rightrotate(w[t-2], 19) ^ (w[t-2] >> 10);
					w[t] = w[t-16] + s0 + w[t-7] + s1;
			  end
		   end
       end
		 /*
		 for (t = 0; t < 64; t++) begin
			$display("\tw[%d] = %x", t, w[t]);
		 end
		 */
	 endfunction
	 
	 function void word_exp_phase3();
		 // WORD EXPANSION
			logic [31:0] t;
        w[0] = h0;
        w[1] = h1;
        w[2] = h2;
        w[3] = h3;
        w[4] = h4;
        w[5] = h5;
        w[6] = h6;
        w[7] = h7;

        w[8] = 32'h80000000; // padding
        for (t = 9; t < 15; t++) begin
            w[t] = 32'h00000000;
        end
        w[15] = 32'd256; // SIZE = 256 BITS

        for (t = 16; t < 64; t++) begin
            s0 = rightrotate(w[t-15], 7) ^ rightrotate(w[t-15], 18) ^ (w[t-15] >> 3);
            s1 = rightrotate(w[t-2], 17) ^ rightrotate(w[t-2], 19) ^ (w[t-2] >> 10);
            w[t] = w[t-16] + s0 + w[t-7] + s1;
        end
	 endfunction
	
	
	
	// Defining States
	enum logic [3:0] {READ_ENABLE=4'b0000, READ=4'b0001, S0=4'b0010, 
		  WRITE=4'b0011, IDLE=4'b0100, S1 = 4'b0101, S2 = 4'b0110, 
		  S3 = 4'b0111, READ_PAUSE=4'b1000, UP_NONCE=4'b1001, PHASE3=4'b1010,
		  PHASE3_FINAL_HASH=4'b1011, S12=4'b1100} state;
		  
		  
	// FSM	  
	always_ff @(posedge clk, negedge reset_n) begin
		if (!reset_n) begin   
			//$display("Inside reset"); 
			state <= IDLE;
		end else
			
		case (state)
		
			IDLE: begin   // IDLE to check start
				if(start) begin
					//$display("Inside IDLE, msg_num = %d", msg_num);
					msg_num <= 0;
					//$display("Printing initial h values");
					//print_h();  // TODO
					state <= READ_ENABLE;
				end
				else state <= IDLE;
			end
			
			READ_ENABLE: begin
				//first = first + 1;
				mem_we <= 0;
				mem_addr <= message_addr + count;
				//$display("Inside READ_ENABLE, msg_num = %d", msg_num);
				
				// TODO
				/*if(count > 0) begin
					$display("temp[%d] = %x", count - 1, temp[count - 1]);
				end */
				
				state <= READ_PAUSE;
				
			end
			
			READ_PAUSE: begin
				state <= READ;
			end
			
			READ: begin
				
				temp[count] <= mem_read_data; // Holds original message
				//$display("temp[%d] = %x", count, temp[count]);
				//$display("Inside READ, msg_num = %d", msg_num);
				//if(first < 2) begin
				//	count <= 0;
				//end else begin
					count <= count + 1;
				//end
				
				if(count > msg_size) begin
					state <= S0;
				end
				else state <= READ_ENABLE;
			end
			
			UP_NONCE: begin
				mem_we <= 0;
			
				nonceCount <= nonceCount + 1;
				//$display("Inside UP_NONCE, msg_num = %d", msg_num);
				
				state <= S1;
			end
			
			S0: begin
				logic [31:0] i;
				
			
			/*	// PADDING AND SIZE
				logic [31:0] m;
				temp[20] = 32'h80000000;
				for (m = 21; m < 31; m++) begin
					  temp[m] <= 32'h00000000;	
				end
				temp[31] <= 32'd640; */
				padding();
				//$display("Inside S0 (PAD), msg_num = %d", msg_num);

				/*$display("Printing TEMP");
				//temp[0] = 32'h1010db8e;  // CHANGE
				for(i = 0; i < 32; i++) begin
					$display("%x\t", temp[i]);
				end */
				
				state <= S1;	
			end
			
			// S1 = word expansion
			S1: begin
				logic [31:0] i;
				
				//$display("Inside S1 (word_exp), msg_num = %d, nonceCount = %d", msg_num, nonceCount);
				
				// INITIALIZE HASH
				if (msg_num < 1 )begin
					//$display("Setting hash inputs, first block");
					 a <= h0;
					 b <= h1;
					 c <= h2;
					 d <= h3;
					 e <= h4;
					 f <= h5;
					 g <= h6;
					 h <= h7;
				end else begin
					//$display("Setting hash inputs, second block");
					 a <= b10;
					 b <= b11;
					 c <= b12;
					 d <= b13;
					 e <= b14;
					 f <= b15;
					 g <= b16;
					 h <= b17;
					// $display("Inside S1 (word_exp) initialize sha256 with block 1 hash");
				end
					 
				 word_exp(msg_num);
				 
				 
				 
			
				 //print_h();
				 /*
				 $display("Printing W");
					for(i = 0; i < 16; i++) begin
						$display("%x\t", w[i]);
					end
				*/
				 
				 state <= S12;
			end
			
			S12: begin
				//prehash
				logic [31:0] t;
				for (t = 0; t < 64; t++) begin   //function call
					//prehash_add[t] = sha256_add(w[t],t);
					sha256_add(w[t],t);
					$display("\tprehash_add[%d] = %x", t, prehash_add[t]);
				end
				
				state <= S2;
			end
			
			S2: begin
				// HASHING
				logic [31:0] t;
				for (t = 0; t < 64; t++) begin   //function call
					// TODO
					{a, b, c, d, e, f, g, h} = sha256_op(a, b, c, d, e, f, g, h, prehash_add[t], t);
				end
				
				//$display("Inside S2 (hash call), msg_num = %d", msg_num);
				
				
				
				if (isPhase3 < 1) begin
					state <= S3;
				end else begin
					state <= PHASE3_FINAL_HASH;
				end

			end
			
			S3: begin
				// FINAL HASH
				//$display("Inside S3 final hash, msg_num = %d", msg_num);
				
				// Hash of block 1, add sha256 to initial hash
				if (msg_num < 1 )begin
					b10 <= h0 + a;
					b11 <= h1 + b;
					b12 <= h2 + c;
					b13 <= h3 + d;
					b14 <= h4 + e;
					b15 <= h5 + f;
					b16 <= h6 + g;
					b17 <= h7 + h;
					//$display("Inside S3 final hash, created hash of block 1");
					
				// Hash of block 2, add sha256 to hash of block 1
				end else begin
					h0 <= b10 + a;
					h1 <= b11 + b;
					h2 <= b12 + c;
					h3 <= b13 + d;
					h4 <= b14 + e;
					h5 <= b15 + f;
					h6 <= b16 + g;
					h7 <= b17 + h;
					//$display("Inside S3 final hash, create hash of block 2 by add onto block 1");
				end
				
				if(msg_num < msg_total) begin
					msg_num <= msg_num + 1;
				end
				
				
				
				/*
				print_abc();
				print_h();
				*/
				
				// If just finished block 1 and now need to do block 2
				if(msg_num < msg_total - 1) begin
					state <= S1;
				// Else finished phase 2 and now need to do phase 3
				end else begin
					state <= PHASE3;
				end
				
			end
			
			PHASE3: begin
				/*
				$display("Inside PHASE3, msg_num = %d", msg_num);
				$display("First hash of block 2");
				$display("\t%x", h0);
				$display("\t%x", h1);
				$display("\t%x", h2);
				$display("\t%x", h3);
				$display("\t%x", h4);
				$display("\t%x", h5);
				$display("\t%x", h6);
				$display("\t%x", h7);
				*/
				 // Initialize hash
				 a <= f0;
				 b <= f1;
				 c <= f2;
				 d <= f3;
				 e <= f4;
				 f <= f5;
				 g <= f6;
				 h <= f7;
				word_exp_phase3();
				
				isPhase3 <= 1;
				
				state <= S2;
			end
			
			PHASE3_FINAL_HASH: begin
			   // FINAL HASH FOR SECOND HASH PHASE 3
				//$display("Inside PHASE3 final hash, msg_num = %d", msg_num);

			  h0 <= f0 + a;
			  h1 <= f1 + b;
			  h2 <= f2 + c;
			  h3 <= f3 + d;
			  h4 <= f4 + e;
			  h5 <= f5 + f;
			  h6 <= f6 + g;
			  h7 <= f7 + h;
			  
			  isPhase3 <= 0;
			  
			  state <= WRITE;
			end
			
			
			WRITE: begin
			
			
				//$display("Inside write, msg_num = %d, nonceCount = %d\n", msg_num, nonceCount);
			
				/*
				$display("\t%x", h0);
				$display("\t%x", h1);
				$display("\t%x", h2);
				$display("\t%x", h3);
				$display("\t%x", h4);
				$display("\t%x", h5);
				$display("\t%x", h6);
				$display("\t%x", h7);
				*/
				
				
				//print_h();
				
				
				
				mem_we <= 1;
				
				mem_addr <= output_addr + nonceCount;
				mem_write_data <= h0;
				

				// If finish writing 16 h0s
				if(nonceCount > totalNonce - 1) begin
					done <= 1;
					state <= IDLE;
				end else begin
					state <= UP_NONCE;
				end
			end
	
		endcase
	end
	
endmodule