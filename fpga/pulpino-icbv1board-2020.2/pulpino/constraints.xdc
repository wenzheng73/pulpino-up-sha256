create_clock -period 20.000 -name clk [get_ports clk]

set_property -dict {PACKAGE_PIN T14 IOSTANDARD LVCMOS33} [get_ports fetch_enable_n]
set_property PULLDOWN true [get_ports fetch_enable_n]
set_property -dict {PACKAGE_PIN D19 IOSTANDARD LVCMOS33} [get_ports rst_n]
set_property PULLUP true [get_ports rst_n]
set_property -dict {PACKAGE_PIN R4 IOSTANDARD LVCMOS15} [get_ports clk]
set_property PULLDOWN true [get_ports clk]
#set_property -dict {PACKAGE_PIN T6 IOSTANDARD LVCMOS15} [get_ports key[3]]

#spi slave
set_property -dict {PACKAGE_PIN F13 IOSTANDARD LVCMOS33} [get_ports spi_clk_i]
set_property PULLDOWN true [get_ports spi_clk_i]
set_property CLOCK_DEDICATED_ROUTE FALSE [get_nets spi_clk_i]
set_property -dict {PACKAGE_PIN C20 IOSTANDARD LVCMOS33} [get_ports spi_cs_i]
set_property PULLDOWN true [get_ports spi_cs_i]
set_property -dict {PACKAGE_PIN C22 IOSTANDARD LVCMOS33} [get_ports spi_sdo0_o]
set_property PULLDOWN true [get_ports spi_sdo0_o]
set_property -dict {PACKAGE_PIN B22 IOSTANDARD LVCMOS33} [get_ports spi_sdi0_i]
set_property PULLDOWN true [get_ports spi_sdi0_i]

#spi master
set_property -dict {PACKAGE_PIN N17 IOSTANDARD LVCMOS33} [get_ports spi_master_clk_o]
set_property PULLDOWN true [get_ports spi_master_clk_o]
set_property -dict {PACKAGE_PIN V14 IOSTANDARD LVCMOS33} [get_ports spi_master_csn0_o]
set_property PULLDOWN true [get_ports spi_master_csn0_o]
set_property -dict {PACKAGE_PIN T16 IOSTANDARD LVCMOS33} [get_ports spi_master_csn1_o]
set_property PULLDOWN true [get_ports spi_master_csn1_o]
set_property -dict {PACKAGE_PIN N14 IOSTANDARD LVCMOS33} [get_ports spi_master_csn2_o]
set_property PULLDOWN true [get_ports spi_master_csn2_o]
set_property -dict {PACKAGE_PIN N15 IOSTANDARD LVCMOS33} [get_ports spi_master_csn3_o]
set_property PULLDOWN true [get_ports spi_master_csn3_o]
set_property -dict {PACKAGE_PIN P14 IOSTANDARD LVCMOS33} [get_ports spi_master_sdo0_o]
set_property PULLDOWN true [get_ports spi_master_sdo0_o]
set_property -dict {PACKAGE_PIN R14 IOSTANDARD LVCMOS33} [get_ports spi_master_sdi0_i]
set_property PULLDOWN true [get_ports spi_master_sdi0_i]

#uart
set_property -dict {PACKAGE_PIN T15 IOSTANDARD LVCMOS33} [get_ports uart_tx]
set_property PULLDOWN true [get_ports uart_tx]
set_property -dict {PACKAGE_PIN V13 IOSTANDARD LVCMOS33} [get_ports uart_rx]
set_property PULLDOWN true [get_ports uart_rx]

#IIC
set_property -dict {PACKAGE_PIN W10 IOSTANDARD LVCMOS33} [get_ports scl]
#set_property PULLDOWN true [get_ports scl]
set_property -dict {PACKAGE_PIN AA9 IOSTANDARD LVCMOS33} [get_ports sda]
#set_property PULLDOWN true [get_ports sda]

#gpio
set_property -dict {PACKAGE_PIN E19 IOSTANDARD LVCMOS33} [get_ports {gpio[0]}]
set_property PULLDOWN true [get_ports {gpio[0]}]
set_property -dict {PACKAGE_PIN G22 IOSTANDARD LVCMOS33} [get_ports {gpio[1]}]
set_property PULLDOWN true [get_ports {gpio[1]}]
set_property -dict {PACKAGE_PIN G21 IOSTANDARD LVCMOS33} [get_ports {gpio[2]}]
set_property PULLDOWN true [get_ports {gpio[2]}]
set_property -dict {PACKAGE_PIN F20 IOSTANDARD LVCMOS33} [get_ports {gpio[3]}]
set_property PULLDOWN true [get_ports {gpio[3]}]
set_property -dict {PACKAGE_PIN F19 IOSTANDARD LVCMOS33} [get_ports {gpio[4]}]
set_property PULLDOWN true [get_ports {gpio[4]}]
set_property -dict {PACKAGE_PIN E17 IOSTANDARD LVCMOS33} [get_ports {gpio[5]}]
set_property PULLDOWN true [get_ports {gpio[5]}]
set_property -dict {PACKAGE_PIN F16 IOSTANDARD LVCMOS33} [get_ports {gpio[6]}]
set_property PULLDOWN true [get_ports {gpio[6]}]
set_property -dict {PACKAGE_PIN E14 IOSTANDARD LVCMOS33} [get_ports {gpio[7]}]
set_property PULLDOWN true [get_ports {gpio[7]}]
set_property -dict {PACKAGE_PIN E13 IOSTANDARD LVCMOS33} [get_ports {gpio[8]}]
set_property PULLDOWN true [get_ports {gpio[8]}]
set_property -dict {PACKAGE_PIN F14 IOSTANDARD LVCMOS33} [get_ports {gpio[9]}]
set_property PULLDOWN true [get_ports {gpio[9]}]
set_property -dict {PACKAGE_PIN D20 IOSTANDARD LVCMOS33} [get_ports {gpio[10]}]
set_property PULLDOWN true [get_ports {gpio[10]}]
set_property -dict {PACKAGE_PIN C19 IOSTANDARD LVCMOS33} [get_ports {gpio[11]}]
set_property PULLDOWN true [get_ports {gpio[11]}]
set_property -dict {PACKAGE_PIN C18 IOSTANDARD LVCMOS33} [get_ports {gpio[12]}]
set_property PULLDOWN true [get_ports {gpio[12]}]
set_property -dict {PACKAGE_PIN B16 IOSTANDARD LVCMOS33} [get_ports {gpio[13]}]
set_property PULLDOWN true [get_ports {gpio[13]}]
set_property -dict {PACKAGE_PIN B15 IOSTANDARD LVCMOS33} [get_ports {gpio[14]}]
set_property PULLDOWN true [get_ports {gpio[14]}]
set_property -dict {PACKAGE_PIN C15 IOSTANDARD LVCMOS33} [get_ports {gpio[15]}]
set_property PULLDOWN true [get_ports {gpio[15]}]
set_property -dict {PACKAGE_PIN C14 IOSTANDARD LVCMOS33} [get_ports {gpio[16]}]
set_property PULLDOWN true [get_ports {gpio[16]}]
set_property -dict {PACKAGE_PIN B13 IOSTANDARD LVCMOS33} [get_ports {gpio[17]}]
set_property PULLDOWN true [get_ports {gpio[17]}]
set_property -dict {PACKAGE_PIN C13 IOSTANDARD LVCMOS33} [get_ports {gpio[18]}]
set_property PULLDOWN true [get_ports {gpio[18]}]
set_property -dict {PACKAGE_PIN V10 IOSTANDARD LVCMOS33} [get_ports {gpio[19]}]
set_property PULLDOWN true [get_ports {gpio[19]}]
set_property -dict {PACKAGE_PIN AB10 IOSTANDARD LVCMOS33} [get_ports {gpio[20]}]
set_property PULLDOWN true [get_ports {gpio[20]}]

#upio
set_property -dict {PACKAGE_PIN U16 IOSTANDARD LVCMOS33} [get_ports {upio[0]}]
set_property PULLDOWN true [get_ports {upio[0]}]
set_property -dict {PACKAGE_PIN Y14 IOSTANDARD LVCMOS33} [get_ports {upio[1]}]
set_property PULLDOWN true [get_ports {upio[1]}]
set_property -dict {PACKAGE_PIN W14 IOSTANDARD LVCMOS33} [get_ports {upio[2]}]
set_property PULLDOWN true [get_ports {upio[2]}]
set_property -dict {PACKAGE_PIN U15 IOSTANDARD LVCMOS33} [get_ports {upio[3]}]
set_property PULLDOWN true [get_ports {upio[3]}]
set_property -dict {PACKAGE_PIN V15 IOSTANDARD LVCMOS33} [get_ports {upio[4]}]
set_property PULLDOWN true [get_ports {upio[4]}]
set_property -dict {PACKAGE_PIN W16 IOSTANDARD LVCMOS33} [get_ports {upio[5]}]
set_property PULLDOWN true [get_ports {upio[5]}]
set_property -dict {PACKAGE_PIN W15 IOSTANDARD LVCMOS33} [get_ports {upio[6]}]
set_property PULLDOWN true [get_ports {upio[6]}]
set_property -dict {PACKAGE_PIN N13 IOSTANDARD LVCMOS33} [get_ports {upio[7]}]
set_property PULLDOWN true [get_ports {upio[7]}]

#JTAG
set_property -dict {PACKAGE_PIN P15 IOSTANDARD LVCMOS33} [get_ports trstn_i]
set_property PULLDOWN true [get_ports trstn_i]
set_property -dict {PACKAGE_PIN R16 IOSTANDARD LVCMOS33} [get_ports tms_i]
set_property PULLDOWN true [get_ports tms_i]
set_property -dict {PACKAGE_PIN P16 IOSTANDARD LVCMOS33} [get_ports tdi_i]
set_property PULLDOWN true [get_ports tdi_i]
set_property -dict {PACKAGE_PIN R17 IOSTANDARD LVCMOS33} [get_ports tdo_o]
set_property PULLDOWN true [get_ports tdo_o]
set_property -dict {PACKAGE_PIN P17 IOSTANDARD LVCMOS33} [get_ports tck_i]
set_property PULLDOWN true [get_ports tck_i]
set_property CLOCK_DEDICATED_ROUTE FALSE [get_nets tck_i]


set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]
set_property BITSTREAM.GENERAL.COMPRESS true [current_design]
set_property BITSTREAM.CONFIG.CONFIGRATE 50 [current_design]
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]
set_property BITSTREAM.CONFIG.SPI_FALL_EDGE Yes [current_design]