#include <stdio.h>
#include "int.h"
#include "event.h"
#include "user_plugin/apb.h"

#define IRQ_UP_IDX 22

// Must use volatile,
// because it is used to communicate between IRQ and main thread.
volatile int g_up_int_triggers = 0;

void ISR_UP() {
    // Clear interrupt within user plugin peripheral
    UP_APB_CMD = UP_CMD_CLR_INT_BIT;
    ICP = 1 << IRQ_UP_IDX;

    ++g_up_int_triggers;
    printf("In User Plugin interrupt\n");
}

void do_check_sha256(int* errors, int msg_num){

    unsigned expect_out [24] = {
                           //message1(0x303030)'s expected output
                           0x2AC9A674, 0x6ACA543A, 0xF8DFF398, 0x94CFE817,
                           0x3AFBA21E, 0xB01C6FAE, 0x33D52947, 0x222855EF,

                           //message2(0x313131)'s expected output
                           0xF6E0A1E2, 0xAC41945A, 0x9AA7FF8A, 0x8AAA0CEB,
                           0xC12A3BCC, 0x981A929A, 0xD5CF810A, 0x090E11AE,                                    

                           //message3(0x323232)'s expected output
                           0x9B871512, 0x327C09CE, 0x91DD649B, 0x3F96A63B,
                           0x7408EF26, 0x7C8CC571, 0x0114E629, 0x730CB61F }; 


    unsigned expect_msg [3] = {
                          0x303030, //message1

                          0x313131, //message2

                          0x323232  //message3
                         };

    //Read message and outputs
    unsigned message = SHA256_MESSAGE;
    if(message != expect_msg[msg_num])
       printf("MESSAGE WRONG! EXPECTED MESSAGE IS 0x%X, WRONG MESSAGE IS 0x%X",expect_msg[msg_num],message);
    else    printf("MESSAGE RIGHT! MESSAGE IS 0x%X \n",message);

    unsigned out [8];

    out[0] = SHA256_OUT0;
    out[1] = SHA256_OUT1;
    out[2] = SHA256_OUT2;
    out[3] = SHA256_OUT3;

    out[4] = SHA256_OUT4;
    out[5] = SHA256_OUT5;
    out[6] = SHA256_OUT6;
    out[7] = SHA256_OUT7;
    
    for(int i = 0; i < 8; i++ ){
        if( out[i] != expect_out[i + msg_num * 8] ){
            ++errors;

            printf("THERE'S AN ERROR WHEN MESSAGE=%X\n, OUTPUT NUMBER = %X \n", message, i);
            printf("EXPECTED OUTPUT IS 0x%X, WRONG OUTPUT IS 0x%X \n", expect_out[i + msg_num * 8], out[i]);}

        else    printf("OUT RIGHT! OUT IS 0x%X \n", out[i] );  
    }
 
    printf("INTURREPT NUM AT ALL IS %X\n",g_up_int_triggers );
}
void check_sha256(int* errors){

    //
    // Global enable User plugin interrupt
    //
    // Clear all events
    ECP = 0xFFFFFFFF;
    // Clear all interrupts
    ICP = 0xFFFFFFFF;
    int_enable();
    IER = IER | (1 << IRQ_UP_IDX); // Enable User plugin interrupt

    // Enable interrupt within user plugin peripheral
    UP_APB_CTRL = UP_CTRL_INT_EN_BIT;
    printf("User Plugin Interrupt has been enabled\n");

    g_up_int_triggers = 0;

    SHA256_MESSAGE = 0x303030;
    
    do_check_sha256(errors, 0);

    SHA256_MESSAGE = 0x313131;
    
    do_check_sha256(errors, 1);

    SHA256_MESSAGE = 0x323232;
    
    do_check_sha256(errors, 2);

}

int main(){

    int errors = 0;
    
    //there for check sha256
    check_sha256(&errors); 
    
    return (errors != 0); }
