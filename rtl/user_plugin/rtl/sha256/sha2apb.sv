`define SHA_REG_CTRL    6'h01 // BASEADDR + 0x04
`define SHA_REG_CMD     6'h02 // BASEADDR + 0x08

`define SHA_REG_STATUS  6'h03 // BASEADDR + 0x0C

`define SHA_REG_ADDRESS 6'h04 // BASEADDR + 0x10 
`define SHA_REG_MESSAGE 6'h05 // BASEADDR + 0x14 
`define SHA_REG_RW      6'h06 // BASEADDR + 0x18  
`define SHA_REG_DIGEST  6'h07 // BASEADDR + 0x1C

`define CTRL_INT_EN_BIT  'd0

`define CMD_CLR_INT_BIT  'd0
`define CMD_SET_INT_BIT  'd1


module sha2apb
#(
    parameter APB_ADDR_WIDTH = 12  //APB slaves are 4KB by default
)
(
    input  logic                      HCLK,
    input  logic                      HRESETn,
    input  logic [APB_ADDR_WIDTH-1:0] PADDR,
    input  logic               [31:0] PWDATA,
    input  logic                      PWRITE,
    input  logic                      PSEL,
    input  logic                      PENABLE,
    output logic               [31:0] PRDATA,
    output logic                      PREADY,
    output logic                      PSLVERR,

    input  logic                [7:0] upio_in_i,
    output logic                [7:0] upio_out_o,
    output logic                [7:0] upio_dir_o,

    output logic                      int_o
);  
    //unused output
    assign upio_out_o = 8'h0;
    assign upio_dir_o = 8'h0;
    ///////////////
    // SHA Logic //
    ///////////////
    logic        cs;
    logic        we;
	logic [1:0]  r_rw;
    logic        valid;
    logic [7:0]  r_address;
    logic [31:0] r_message;
    
    wire  [31:0] hashed_data;//hashed_data can't write, it's the data-hashed from sha256
    reg   [31:0] r_hashed_data;//store the hashed_data 
    ///////////////
    // APB Logic //
    ///////////////
    assign PSLVERR     = 1'b0;    // No slave error

    logic [5:0] s_apb_addr;
    logic       s_apb_write;
    logic       s_apb_read;

    assign s_apb_addr  = PADDR[7:2];

    ////////////////
    // registers  //
    ////////////////

    logic [31:0] unused_data; // for unused PWDATA
    logic [7:0] r_ctrl;       // ctrl register
    logic [7:0] s_status;     // status register

    logic hash_flag;          // the real hash_flag

    logic s_int_en;           // Interrupt enable
    logic r_int_flag;         // Interrupt pending flag

    assign s_status = {7'b0, r_int_flag}; 
    assign s_int_en = r_ctrl[`CTRL_INT_EN_BIT];

    assign int_o    = s_int_en & r_int_flag;
    
    /////////////////
    // hashed data //
    /////////////////	    
    always_ff @ (posedge HCLK, negedge HRESETn)
        if (~HRESETn)
            r_hashed_data <= 'b0;
        else if(valid)
            r_hashed_data <= hashed_data;
	  
    ////////////////////
    // interrupt flag //
    ////////////////////	  
    always_ff @ (posedge HCLK, negedge HRESETn)
        if(!HRESETn)
            r_int_flag <= 1'b0;
        else if(s_apb_write & (s_apb_addr == `SHA_REG_CMD)) 
        begin
            if (PWDATA[`CMD_CLR_INT_BIT])
                r_int_flag <= 1'b0;
            else if (PWDATA[`CMD_SET_INT_BIT])
                r_int_flag <= 1'b1;
        end
              
    ///////////////
    // hash flag //
    ///////////////
    always_ff@(posedge HCLK or negedge HRESETn)
        if(!HRESETn)
            hash_flag <= 1'b0;
        else if(valid)
            hash_flag <= 1'b0;
        else if(s_apb_write & (s_apb_addr == `SHA_REG_MESSAGE))
            hash_flag <= 1'b1;
  
    //////////////////
    // StateMachine //
    //////////////////
    enum logic [1:0] {
              IDLE,
              WAIT_WRITE,
              WAIT_READ
              } r_stm, s_stm_n;

    always_ff @ (posedge HCLK, negedge HRESETn)
        if (~HRESETn)
            r_stm <= IDLE;
        else
            r_stm <= s_stm_n;

    always_comb
    begin
        PREADY = 1'b0;        
        s_apb_write = 1'b0;
        s_apb_read = 1'b0;

        case (r_stm)
            IDLE:begin
                if(PSEL && PENABLE && PWRITE)
	            s_stm_n = WAIT_WRITE;
                else if(PSEL && PENABLE && (!PWRITE))
                    s_stm_n = WAIT_READ;
                else s_stm_n = IDLE;
            end
  	             
            WAIT_WRITE:begin
       	        PREADY = 1'b1;
                s_apb_write = 1'b1;
                s_stm_n = IDLE;
            end
    
            WAIT_READ:begin
                PREADY = 1'b1;
                s_apb_read = 1'b1;
                s_stm_n = IDLE;
            end
                        
            default:
                s_stm_n = IDLE;
        endcase
    end
    
    ///////////////
    // REG write //
    ///////////////
    always_ff @ (posedge HCLK, negedge HRESETn)
    begin
        if (~HRESETn) begin
            r_ctrl      <= 8'd0;
            r_rw        <= 2'b00;
            r_address   <= 8'd0;
            r_message   <= 32'd0;
            unused_data <= 32'd0;
        end
        else if (s_apb_write) begin
            case (s_apb_addr)
                `SHA_REG_CTRL:
                    r_ctrl <= PWDATA[7:0];
                `SHA_REG_RW:
                    r_rw <= PWDATA[7:0];
                `SHA_REG_ADDRESS:
                    r_address <= PWDATA[7:0];
                `SHA_REG_MESSAGE:
                    r_message <= PWDATA;
                default:
                    unused_data <= PWDATA; 
            endcase
        end
    end 

    //////////////
    // REG READ //
    //////////////
    always_comb 
    begin
        case (s_apb_addr)
            `SHA_REG_CTRL:
                PRDATA = {24'b0, r_ctrl};
            `SHA_REG_STATUS:
                PRDATA = {24'b0, s_status};
            `SHA_REG_MESSAGE:
                PRDATA = r_message;
            `SHA_REG_DIGEST:
                PRDATA = r_hashed_data;
            default:
                PRDATA = 'b0;//for unused PADDR
        endcase 
    end
    /////////////////////
    //SHA256 Read_Write//
    /////////////////////
    assign cs = r_rw[1];
    assign we = r_rw[0];
    //
    sha256	sha256_top
    (
	      .clk(HCLK),
	      .reset_n(HRESETn),
          
          //control
          .cs(cs),
          .we(we),

          //data ports
	      .address(r_address),    //input [7:0]
	      .write_data(r_message), //input [31:0] .
      
	      .read_data(hashed_data),
	      .valid(valid)
    );
endmodule
