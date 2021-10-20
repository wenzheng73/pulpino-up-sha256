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

void show_and_check_regs(int* errors, unsigned expected_ctrl, unsigned expected_status) {
    // cmd reg is always zero, when reading
    unsigned expected_cmd = 0;

    unsigned ctrl = UP_APB_CTRL;
    unsigned cmd = UP_APB_CMD;
    unsigned status = UP_APB_STATUS;

    printf("ctrl: 0x%X\n", ctrl);
    printf("cmd: 0x%X\n", cmd);
    printf("status: 0x%X\n", status);
    if (ctrl != expected_ctrl) {
        ++(*errors);
        printf("Expected ctrl reg: 0x%X, but got: 0x%X\n", expected_ctrl, ctrl);
    }
    if (cmd != expected_cmd) {
        ++(*errors);
        printf("Expected cmd reg: 0x%X, but got: 0x%X\n", expected_cmd, cmd);
    }
    if (status != expected_status) {
        ++(*errors);
        printf("Expected status reg: 0x%X, but got: 0x%X\n", expected_status, status);
    }
}

void check_ABS(int* errors) {
    UP_APB_A = 0x05;
    UP_APB_B = 0xA0;
    unsigned expected = 0x05 | 0xA0;

    unsigned a = UP_APB_A;
    unsigned b = UP_APB_B;
    unsigned s = UP_APB_S;

    printf("A = 0x%X, B = 0x%X, S = 0x%X\n", a, b, s);
    if (s != expected) {
        ++(*errors);
        printf("Expect 0x%X, but got 0x%X\n", expected, s);
    }
}

// Check ctrl / cmd / status regs behavior without irq.
void check_ccs_no_irq(int* errors) {
    printf("Initial ctrl/status values:\n");
    show_and_check_regs(errors, 0, 0);

    // Enable interrupt
    UP_APB_CTRL = UP_CTRL_INT_EN_BIT;
    printf("User Plugin Interrupt enabled\n");
    show_and_check_regs(errors, UP_CTRL_INT_EN_BIT, 0);;

    // Set interrupt pending
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    printf("User Plugin Interrupt pending set\n");
    show_and_check_regs(errors, UP_CTRL_INT_EN_BIT, UP_STATUS_INT_BIT);

    // Clear interrupt pending
    UP_APB_CMD = UP_CMD_CLR_INT_BIT;
    printf("User Plugin Interrupt pending set\n");
    show_and_check_regs(errors, UP_CTRL_INT_EN_BIT, 0);

    // Set interrupt pending
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    // Disable interrupt
    UP_APB_CTRL = 0;
    printf("User Plugin Interrupt pending set, but interrupt disabled\n");
    show_and_check_regs(errors, 0, UP_STATUS_INT_BIT);
}

// Check ctrl / cmd / status regs behavior with irq.
void check_ccs_irq(int* errors) {
    //
    // Make sure no irq pending
    //
    // Disable irq within user plugin peripherals.
    UP_APB_CTRL = 0;
    // Clear pending int
    UP_APB_CMD = UP_CMD_CLR_INT_BIT;

    //
    // Global enable User plugin interrupt
    //
    // Clear all events
    ECP = 0xFFFFFFFF;
    // Clear all interrupts
    ICP = 0xFFFFFFFF;
    int_enable();
    IER = IER | (1 << IRQ_UP_IDX); // Enable User plugin interrupt

    g_up_int_triggers = 0;

    // Enable interrupt within user plugin peripheral
    UP_APB_CTRL = UP_CTRL_INT_EN_BIT;
    // Set interrupt pending, and interrupt handler will be called.
    printf("User Plugin Interrupt has been enabled\n");
    printf("Going to set int pending bit, and int handler will be called\n");
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    // For zeroriscy cpu core, the interrupt is handled after one 'nop'.
    // For ri5cy cpu core, the interrupt is handled after two 'nop's.
    asm volatile("nop");
    asm volatile("nop");

    if (g_up_int_triggers != 1) {
        ++(*errors);
        printf("Expect to enter interrupt handler once, but actual number: %d\n", g_up_int_triggers);
    }
}

int main(){
    int errors = 0;

    check_ABS(&errors);
    check_ccs_no_irq(&errors);
    check_ccs_irq(&errors);
    return !(errors == 0);
}
