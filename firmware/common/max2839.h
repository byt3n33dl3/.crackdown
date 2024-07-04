/*
 * Copyright 2012-2022 Great Scott Gadgets <info@greatscottgadgets.com>
 * Copyright 2012 Will Code <willcode4@gmail.com>
 * Copyright 2014 Jared Boone <jared@sharebrained.com>
 *
 * This file is part of HackRF.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef __MAX2839_H
#define __MAX2839_H

#include <stdint.h>
#include <stdbool.h>

#include "gpio.h"
#include "spi_bus.h"

/* 32 registers, each containing 10 bits of data. */
#define MAX2839_NUM_REGS            32
#define MAX2839_DATA_REGS_MAX_VALUE 1024

typedef enum {
	MAX2839_MODE_SHUTDOWN,
	MAX2839_MODE_STANDBY,
	MAX2839_MODE_TX,
	MAX2839_MODE_RX,
	MAX2839_MODE_RX_CAL,
	MAX2839_MODE_TX_CAL,
	MAX2839_MODE_CLKOUT,
} max2839_mode_t;

struct max2839_driver_t;
typedef struct max2839_driver_t max2839_driver_t;

struct max2839_driver_t {
	spi_bus_t* bus;
	gpio_t gpio_enable;
	gpio_t gpio_rxtx;
	void (*target_init)(max2839_driver_t* const drv);
	void (*set_mode)(max2839_driver_t* const drv, const max2839_mode_t new_mode);
	max2839_mode_t mode;
	uint16_t regs[MAX2839_NUM_REGS];
	uint32_t regs_dirty;
};

/* Initialize chip. */
extern void max2839_setup(max2839_driver_t* const drv);

/* Read a register via SPI. Save a copy to memory and return
 * value. Mark clean. */
extern uint16_t max2839_reg_read(max2839_driver_t* const drv, uint8_t r);

/* Write value to register via SPI and save a copy to memory. Mark
 * clean. */
extern void max2839_reg_write(max2839_driver_t* const drv, uint8_t r, uint16_t v);

/* Write all dirty registers via SPI from memory. Mark all clean. Some
 * operations require registers to be written in a certain order. Use
 * provided routines for those operations. */
extern void max2839_regs_commit(max2839_driver_t* const drv);

max2839_mode_t max2839_mode(max2839_driver_t* const drv);
void max2839_set_mode(max2839_driver_t* const drv, const max2839_mode_t new_mode);

/* Turn on/off all chip functions. Does not control oscillator and CLKOUT */
extern void max2839_start(max2839_driver_t* const drv);
extern void max2839_stop(max2839_driver_t* const drv);

/* Set frequency in Hz. Frequency setting is a multi-step function
 * where order of register writes matters. */
extern void max2839_set_frequency(max2839_driver_t* const drv, uint32_t freq);
uint32_t max2839_set_lpf_bandwidth(
	max2839_driver_t* const drv,
	const uint32_t bandwidth_hz);
bool max2839_set_lna_gain(max2839_driver_t* const drv, const uint32_t gain_db);
bool max2839_set_vga_gain(max2839_driver_t* const drv, const uint32_t gain_db);
bool max2839_set_txvga_gain(max2839_driver_t* const drv, const uint32_t gain_db);

extern void max2839_tx(max2839_driver_t* const drv);
extern void max2839_rx(max2839_driver_t* const drv);

#endif // __MAX2839_H
