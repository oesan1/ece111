module simplified_sha256(input logic clk, reset_n, start,
	input logic [15:0] message_addr, output_addr,
	output logic done, mem_clk, mem_we,
	output logic [15:0] mem_addr,
	output logic [31:0] mem_write_data,
	input logic [31:0] mem_read_data);

	assign mem_clk = clk;
	logic	  [31:0] temp[32];
	logic   [31:0] w[64];
	logic   [31:0] s1, s0;
	logic   [31:0] a, b, c, d, e, f, g, h;
	logic   [15:0] count = 0;
	logic   [15:0] msg_size = 20;
	logic   [31:0] value;
	logic	  [7:0] msg_num = 0;
	logic   [7:0] msg_total = 2;
	logic   [31:0] first = 0;
	
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
	logic [31:0]  h0 = 32'h6a09e667,	// these are from slides!!!! (dont know what the Hs are. Are they from spreadsheet?)
					  h1 = 32'hbb67ae85,
					  h2 = 32'h3c6ef372,
					  h3 = 32'ha54ff53a,
					  h4 = 32'h510e527f,
					  h5 = 32'h9b05688c,
					  h6 = 32'h1f83d9ab,
					  h7 = 32'h5be0cd19;

	
	// right rotation
	function logic [31:0] rightrotate(input logic [31:0] x,
		input logic [ 7:0] r);
		rightrotate = (x >> r) | (x << (32-r));
	endfunction
	
	// SHA256 hash round
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
												input logic [7:0] t);
		logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
		begin
			 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
			 ch = (e & f) ^ ((~e) & g);
			 t1 = h + S1 + ch + sha256_k[t] + w;
			 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
			 maj = (a & b) ^ (a & c) ^ (b & c);
			 t2 = S0 + maj;

			 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
		end
	endfunction
	
	function void padding();		// change to void later just to see
		logic [31:0] m;
		begin
			temp[20] = 32'h80000000;
			for (m = 21; m < 31; m++) begin
				  temp[m] = 32'h00000000;	
			end
			temp[31] = 32'd640; 
			
		end
	endfunction
	
	function void word_exp(msg_num);
		logic [31:0] t;
		logic [31:0] sub_temp[16];
		
		if(msg_num == 0) begin
			sub_temp = temp[0:15];
		end else begin
			sub_temp = temp[16:31];
		end
		
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
	 endfunction
	
	
	
	
	// Defining States
	enum logic [2:0] {READ_ENABLE=4'b0000, READ=4'b0001, S0=4'b0010, 
		  WRITE=4'b0011, IDLE=4'b0100, S1 = 4'b0101, S2 = 4'b0110, 
		  S3 = 4'b0111, READ_PAUSE=4'b1000} state;
		  
		  
	// FSM	  
	always_ff @(posedge clk, negedge reset_n) begin
		if (!reset_n) begin   
			$display("Inside reset\n");
			state <= IDLE;
		end else
			
		case (state)
		
			IDLE: begin   // IDLE to check start
				if(start) begin
					$display("Inside IDLE, msg_num = %d", msg_num);
					state <= READ_ENABLE;
				end
				else state <= IDLE;
			end
			
			READ_ENABLE: begin
				//first = first + 1;
				mem_we <= 0;
				mem_addr <= message_addr + count;
				$display("Inside READ_ENABLE, msg_num = %d", msg_num);
				
				if(count > 0) begin
					$display("temp[%d] = %x", count - 1, temp[count - 1]);
				end
				
				state <= READ_PAUSE;
				
			end
			
			READ_PAUSE: begin
				state <= READ
			end
			
			READ: begin
				
				temp[count] <= mem_read_data; 
				//$display("temp[%d] = %x", count, temp[count]);
				$display("Inside READ, msg_num = %d", msg_num);
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
				$display("Inside S0 (PAD), msg_num = %d\n", msg_num);

				$display("Printing TEMP");
				//temp[0] = 32'h1010db8e;  // CHANGE
				for(i = 0; i < 32; i++) begin
					$display("%x\t", temp[i]);
				end
				
				state <= S1;	
			end
			
			S1: begin
				logic [31:0] i;
				// INITIALIZE HASH
				 a <= h0;
				 b <= h1;
				 c <= h2;
				 d <= h3;
				 e <= h4;
				 f <= h5;
				 g <= h6;
				 h <= h7;
				 
				 word_exp(msg_num);
				 
				 
				 $display("Inside S1 (word_exp), msg_num = %d", msg_num);
				 
				 $display("Printing W");
					for(i = 0; i < 16; i++) begin
						$display("%x\t", w[i]);
					end
				
				 
				 state <= S2;
			end
			
			S2: begin
				// HASHING
				logic [31:0] t;
				for (t = 0; t < 64; t++) begin   //function call
					{a, b, c, d, e, f, g, h} = sha256_op(a, b, c, d, e, f, g, h, w[t], t);
				end
				
				$display("Inside S2 (hash call), msg_num = %d", msg_num);
				
				state <= S3;

			end
			
			S3: begin
				// FINAL HASH
				
				h0 <= h0 + a;
				h1 <= h1 + b;
				h2 <= h2 + c;
				h3 <= h3 + d;
				h4 <= h4 + e;
				h5 <= h5 + f;
				h6 <= h6 + g;
				h7 <= h7 + h;
				
				msg_num = msg_num + 1;
				
				$display("Inside final hash, msg_num = %d", msg_num);
				
				if(msg_num < msg_total) begin
					state <= S1;
				end else begin
					state <= WRITE;
				end
				
			end
			
			WRITE: begin
				$display("Inside write, msg_num = %d", msg_num);
				mem_we <= 1;
				
				mem_addr <= output_addr;
				mem_write_data <= h0;
				
				mem_addr <= output_addr +1;
				mem_write_data <= h1;
				
				mem_addr <= output_addr +2;
				mem_write_data <= h2;
				
				mem_addr <= output_addr +3;
				mem_write_data <= h3;
				
				mem_addr <= output_addr +4;
				mem_write_data <= h4;
				
				mem_addr <= output_addr +5;
				mem_write_data <= h5;
				
				mem_addr <= output_addr +6;
				mem_write_data <= h6;
				
				mem_addr <= output_addr +7;
				mem_write_data <= h7;
				
				done <= 1;
				state <= IDLE;
			end
	
		endcase
	end
	
endmodule