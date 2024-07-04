/*
 * Copyright 2012-2022 Great Scott Gadgets <info@greatscottgadgets.com>
 * Copyright 2012 Jared Boone <jared@sharebrained.com>
 * Copyright 2013 Benjamin Vernoux <titanmkd@gmail.com>
 * Copyright 2017 Schuyler St. Leger <schuyler.st.leger@gmail.com>
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

#include <libopencm3/lpc43xx/scu.h>
#include <libopencm3/lpc43xx/sgpio.h>

#include "hackrf_core.h"
#include "platform_detect.h"

#include "sgpio.h"

static void update_q_invert(sgpio_config_t* const config);

void sgpio_configure_pin_functions(sgpio_config_t* const config)
{
	scu_pinmux(SCU_PINMUX_SGPIO0, SCU_GPIO_FAST | SCU_CONF_FUNCTION3);
	scu_pinmux(SCU_PINMUX_SGPIO1, SCU_GPIO_FAST | SCU_CONF_FUNCTION3);
	scu_pinmux(SCU_PINMUX_SGPIO2, SCU_GPIO_FAST | SCU_CONF_FUNCTION2);
	scu_pinmux(SCU_PINMUX_SGPIO3, SCU_GPIO_FAST | SCU_CONF_FUNCTION2);
	scu_pinmux(SCU_PINMUX_SGPIO4, SCU_GPIO_FAST | SCU_CONF_FUNCTION2);
	scu_pinmux(SCU_PINMUX_SGPIO5, SCU_GPIO_FAST | SCU_CONF_FUNCTION2);
	scu_pinmux(SCU_PINMUX_SGPIO6, SCU_GPIO_FAST | SCU_CONF_FUNCTION0);
	scu_pinmux(SCU_PINMUX_SGPIO7, SCU_GPIO_FAST | SCU_CONF_FUNCTION6);
	scu_pinmux(SCU_PINMUX_SGPIO8, SCU_GPIO_FAST | SCU_CONF_FUNCTION6);
	scu_pinmux(SCU_PINMUX_SGPIO9, SCU_GPIO_FAST | SCU_CONF_FUNCTION7);
	scu_pinmux(SCU_PINMUX_SGPIO10, SCU_GPIO_FAST | SCU_CONF_FUNCTION6);
	scu_pinmux(SCU_PINMUX_SGPIO11, SCU_GPIO_FAST | SCU_CONF_FUNCTION6);
	scu_pinmux(SCU_PINMUX_SGPIO12, SCU_GPIO_FAST | SCU_CONF_FUNCTION0); /* GPIO0[13] */
	scu_pinmux(SCU_PINMUX_SGPIO14, SCU_GPIO_FAST | SCU_CONF_FUNCTION4); /* GPIO5[13] */
	scu_pinmux(SCU_PINMUX_SGPIO15, SCU_GPIO_FAST | SCU_CONF_FUNCTION4); /* GPIO5[14] */

	if (detected_platform() == BOARD_ID_HACKRF1_R9) {
		scu_pinmux(
			SCU_H1R9_HW_SYNC_EN,
			SCU_GPIO_FAST | SCU_CONF_FUNCTION4); /* GPIO5[5] */
	} else {
		scu_pinmux(
			SCU_HW_SYNC_EN,
			SCU_GPIO_FAST | SCU_CONF_FUNCTION4); /* GPIO5[12] */
	}

	sgpio_cpld_set_mixer_invert(config, 0);
	hw_sync_enable(0);

	gpio_output(config->gpio_q_invert);
	gpio_output(config->gpio_hw_sync_enable);
}

void sgpio_set_slice_mode(sgpio_config_t* const config, const bool multi_slice)
{
	config->slice_mode_multislice = multi_slice;
}

/*
 SGPIO 0 to 7 = DAC/ADC data bits 0 to 7
 (Note: DAC is 10 bits but only bit 9 to bit 2 are used, bits 1 & 0 are forced to 0 by CPLD)

 ADC => CLK x 2 = CLKx2 with
   CLKx2(0) rising = D0Q,
   CLKx2(1) rising = D1I
 Corresponds to:
   CLK(0) falling + tD0Q => D0Q,
   CLK(1) rising  + tDOI => D1I,
   CLK(1) falling + tD0Q => D1Q,
   CLK(1) rising  + tDOI => D2I ...)
 tDOI(CLK Rise to I-ADC Channel-I Output Data Valid) = 7.4 to 9ns
 tD0Q(CLK Fall to Q-ADC Channel-Q Output Data Valid) = 6.9 to 9ns

 DAC=> CLK x 2 = CLKx2 with:
   CLKx2(0) rising = Q:N-2,
   CLKx2(1) rising = I:N-1
 Corresponds to:
   CLK(0) rising  => Q:N-2,
   CLK(0) falling => I:N-1,
   CLK(1) rising  => Q:N-1,
   CLK(1) falling => I:N ...
 tDSI(I-DAC Data to CLK Fall Setup Time) = min 10ns
 tDSQ(Q-DAC Data to CLK Rise Setup Time) = min 10ns

 SGPIO8 Clock Input (External Clock)
 SGPIO9 Capture Input (Capture/ChipSelect, 1=Enable Capture, 0=Disable capture)
 SGPIO10 Disable Output (1/High=Disable codec data stream, 0/Low=Enable codec data stream)
 SGPIO11 Direction Output (1/High=TX mode LPC43xx=>CPLD=>DAC, 0/Low=RX mode LPC43xx<=CPLD<=ADC)
*/
void sgpio_configure(sgpio_config_t* const config, const sgpio_direction_t direction)
{
	// Disable all counters during configuration
	SGPIO_CTRL_ENABLE = 0;

	// Set SGPIO output values.
	const uint_fast8_t cpld_direction = (direction == SGPIO_DIRECTION_TX) ? 1 : 0;

	// clang-format off
	SGPIO_GPIO_OUTREG =
		  (cpld_direction << 11) // 1 = Output SGPIO11 High (TX mode)
		                         // 0 = Output SGPIO11 Low  (RX mode)
		| (1L << 10) // disable codec data stream during configuration
		             // (Output SGPIO10 High)
		;
	// clang-format on

	/* The data direction might have changed. Check if we need to
	 * adjust the q inversion. */
	update_q_invert(config);

	// Enable SGPIO pin outputs.
	const uint_fast16_t sgpio_gpio_data_direction =
		(direction == SGPIO_DIRECTION_TX) ? (0xFF << 0) : (0x00 << 0);

	// clang-format off
	SGPIO_GPIO_OENREG =
		  (1L << 14) // GPDMA burst request SGPIO14 active
		| (1L << 11) // direction output SGPIO11 active
		| (1L << 10) // disable output SGPIO10 active
		| (0L <<  9) // capture input SGPIO9 (output i is tri-stated)
		| (0L <<  8) // clock input SGPIO8 (output i is tri-stated)
		| sgpio_gpio_data_direction // 0xFF = Output all SGPIO High (TX mode)
		;                           // 0x00 = Output all SPGIO Low  (RX mode)

	SGPIO_OUT_MUX_CFG( 8) = // SGPIO8:
		  SGPIO_OUT_MUX_CFG_P_OE_CFG(0)  // gpio_oe (state set by GPIO_OEREG)
		| SGPIO_OUT_MUX_CFG_P_OUT_CFG(0) // dout_doutm1 (1-bit mode)
		;
	SGPIO_OUT_MUX_CFG( 9) = // SGPIO9: Input: qualifier
		  SGPIO_OUT_MUX_CFG_P_OE_CFG(0)  // gpio_oe (state set by GPIO_OEREG)
		| SGPIO_OUT_MUX_CFG_P_OUT_CFG(0) // dout_doutm1 (1-bit mode)
		;
    SGPIO_OUT_MUX_CFG(10) = // GPIO10: Output: disable
		  SGPIO_OUT_MUX_CFG_P_OE_CFG(0)  // gpio_oe (state set by GPIO_OEREG)
		| SGPIO_OUT_MUX_CFG_P_OUT_CFG(4) // gpio_out (level set by GPIO_OUTREG)
		;
    SGPIO_OUT_MUX_CFG(11) = // GPIO11: Output: direction
		  SGPIO_OUT_MUX_CFG_P_OE_CFG(0)  // gpio_oe (state set by GPIO_OEREG)
		| SGPIO_OUT_MUX_CFG_P_OUT_CFG(4) // gpio_out (level set by GPIO_OUTREG)
		;
	SGPIO_OUT_MUX_CFG(14) = // SGPIO14: Output: internal GPDMA burst request
		  SGPIO_OUT_MUX_CFG_P_OE_CFG(0)  // dout_oem1 (1-bit mode)
		| SGPIO_OUT_MUX_CFG_P_OUT_CFG(0) // dout_doutm1 (1-bit mode)
		;
	// clang-format on

	const uint_fast8_t output_multiplexing_mode =
		config->slice_mode_multislice ? 11 : 9;
	/* SGPIO0 to SGPIO7 */
	for (uint_fast8_t i = 0; i < 8; i++) {
		// SGPIO pin 0 outputs slice A bit "i".
		SGPIO_OUT_MUX_CFG(i) = SGPIO_OUT_MUX_CFG_P_OE_CFG(0)
			// 11 = dout_doutm8c (8-bit mode 8c) (multislice L0/7, N0/7)
			// 9  = dout_doutm8a (8-bit mode 8a) (A0/7, B0/7)
			| SGPIO_OUT_MUX_CFG_P_OUT_CFG(output_multiplexing_mode);
	}

	const uint_fast8_t slice_indices[] = {
		SGPIO_SLICE_A,
		SGPIO_SLICE_I,
		SGPIO_SLICE_E,
		SGPIO_SLICE_J,
		SGPIO_SLICE_C,
		SGPIO_SLICE_K,
		SGPIO_SLICE_F,
		SGPIO_SLICE_L,
	};
	const uint_fast8_t slice_gpdma = SGPIO_SLICE_H;

	const uint_fast8_t pos = config->slice_mode_multislice ? 0x1f : 0x03;
	const bool single_slice = !config->slice_mode_multislice;
	const uint_fast8_t slice_count = config->slice_mode_multislice ? 8 : 1;

	// Also enable slice D for clkout to the SCTimer
	uint32_t slice_enable_mask = BIT3;

	/* Configure Slice A, I, E, J, C, K, F, L (sgpio_slice_mode_multislice mode) */
	for (uint_fast8_t i = 0; i < slice_count; i++) {
		const uint_fast8_t slice_index = slice_indices[i];
		/* Only for slice0/A and RX mode set input_slice to 1 */
		const bool input_slice = (i == 0) && (direction != SGPIO_DIRECTION_TX);
		/* 0 = Self-loop (slice0/A RX mode), 3 = 8 slices */
		const uint_fast8_t concat_order = (input_slice || single_slice) ? 0 : 3;
		/* 0 = External data pin (slice0/A RX mode), 1 = Concatenate data */
		const uint_fast8_t concat_enable = (input_slice || single_slice) ? 0 : 1;

		// clang-format off
		SGPIO_MUX_CFG(slice_index) =
			  SGPIO_MUX_CFG_CONCAT_ORDER(concat_order)
			| SGPIO_MUX_CFG_CONCAT_ENABLE(concat_enable)
			| SGPIO_MUX_CFG_QUALIFIER_SLICE_MODE(0)  // Select qualifier slice A
			| SGPIO_MUX_CFG_QUALIFIER_PIN_MODE(1)    // Select qualifier pin SGPIO9
			| SGPIO_MUX_CFG_QUALIFIER_MODE(3)        // External SGPIO
			| SGPIO_MUX_CFG_CLK_SOURCE_SLICE_MODE(0) // Select clock source slice D
			| SGPIO_MUX_CFG_CLK_SOURCE_PIN_MODE(0)   // Source clock pin = SGPIO8
			| SGPIO_MUX_CFG_EXT_CLK_ENABLE(1)        // External clock signal selected
			;
		SGPIO_SLICE_MUX_CFG(slice_index) =
			  SGPIO_SLICE_MUX_CFG_INV_QUALIFIER(0)     // Use normal qualifier
			| SGPIO_SLICE_MUX_CFG_PARALLEL_MODE(3)     // Shift 1 byte (8 bits) per clock
			| SGPIO_SLICE_MUX_CFG_DATA_CAPTURE_MODE(0) // Detect rising edge
			| SGPIO_SLICE_MUX_CFG_INV_OUT_CLK(0)       // Normal clock
			| SGPIO_SLICE_MUX_CFG_CLKGEN_MODE(1)       // Use external clock from a pin or other slice
			| SGPIO_SLICE_MUX_CFG_CLK_CAPTURE_MODE(0)  // Use rising clock edge
			| SGPIO_SLICE_MUX_CFG_MATCH_MODE(0)        // Do not match data
			;
		// clang-format on

		SGPIO_PRESET(slice_index) = 0; // External clock, don't care
		SGPIO_COUNT(slice_index) = 0;  // External clock, don't care
		SGPIO_POS(slice_index) = SGPIO_POS_POS_RESET(pos) | SGPIO_POS_POS(pos);
		SGPIO_REG(slice_index) = 0x00000000;    // Primary output data register
		SGPIO_REG_SS(slice_index) = 0x00000000; // Shadow output data register
		// clang-format on

		slice_enable_mask |= (1 << slice_index);
	}

	if (config->slice_mode_multislice == false) {
		// clang-format off
		SGPIO_MUX_CFG(slice_gpdma) =
			  SGPIO_MUX_CFG_CONCAT_ORDER(0)          // Self-loop
			| SGPIO_MUX_CFG_CONCAT_ENABLE(1)         // Concatenate data
			| SGPIO_MUX_CFG_QUALIFIER_SLICE_MODE(0)  // Select qualifier slice A
			| SGPIO_MUX_CFG_QUALIFIER_PIN_MODE(1)    // Select qualifier pin SGPIO9
			| SGPIO_MUX_CFG_QUALIFIER_MODE(3)        // External SGPIO
			| SGPIO_MUX_CFG_CLK_SOURCE_SLICE_MODE(0) // Select clock source slice D
			| SGPIO_MUX_CFG_CLK_SOURCE_PIN_MODE(0)   // Source clock pin = SGPIO8
			| SGPIO_MUX_CFG_EXT_CLK_ENABLE(1)        // External clock signal selected
			;
		SGPIO_SLICE_MUX_CFG(slice_gpdma) =
			  SGPIO_SLICE_MUX_CFG_INV_QUALIFIER(0)     // Use normal qualifier
			| SGPIO_SLICE_MUX_CFG_PARALLEL_MODE(0)     // Shift 1 bit per clock
			| SGPIO_SLICE_MUX_CFG_DATA_CAPTURE_MODE(0) // Detect rising edge
			| SGPIO_SLICE_MUX_CFG_INV_OUT_CLK(0)       // Normal clock
			| SGPIO_SLICE_MUX_CFG_CLKGEN_MODE(1)       // Use external clock from a pin or other slice
			| SGPIO_SLICE_MUX_CFG_CLK_CAPTURE_MODE(0)  // Use rising clock edge
			| SGPIO_SLICE_MUX_CFG_MATCH_MODE(0)        // Do not match data
			;
		// clang-format on

		SGPIO_PRESET(slice_gpdma) = 0; // External clock, don't care
		SGPIO_COUNT(slice_gpdma) = 0;  // External clock, don't care
		SGPIO_POS(slice_gpdma) = SGPIO_POS_POS_RESET(0x1f) | SGPIO_POS_POS(0x1f);
		SGPIO_REG(slice_gpdma) =
			0x11111111; // Primary output data register, LSB -> out
		SGPIO_REG_SS(slice_gpdma) =
			0x11111111; // Shadow output data register, LSB -> out1

		slice_enable_mask |= (1 << slice_gpdma);
	}

	// Start SGPIO operation by enabling slice clocks.
	SGPIO_CTRL_ENABLE = slice_enable_mask;
}

void sgpio_cpld_stream_enable(sgpio_config_t* const config)
{
	(void) config;
	// Enable codec data stream.
	SGPIO_GPIO_OUTREG &= ~(1L << 10); /* SGPIO10 */
}

void sgpio_cpld_stream_disable(sgpio_config_t* const config)
{
	(void) config;
	// Disable codec data stream.
	SGPIO_GPIO_OUTREG |= (1L << 10); /* SGPIO10 */
}

bool sgpio_cpld_stream_is_enabled(sgpio_config_t* const config)
{
	(void) config;
	return (SGPIO_GPIO_OUTREG & (1L << 10)) == 0; /* SGPIO10 */
}

/*
 * The spectrum can be inverted by the analog section of the hardware in two
 * different ways:
 *
 * - The front-end mixer can introduce an inversion depending on the frequency
 *   tuning configuration.
 *
 * - Routing of the analog baseband signals can introduce an inversion
 *   depending on the design of the hardware platform and whether we are in RX
 *   or TX mode.
 *
 * When one but not both of the above effects inverts the spectrum, we instruct
 * the CPLD to correct the inversion by inverting the Q sample value.
 */
static bool mixer_invert = false;

/* Called when TX/RX changes or sgpio_cpld_set_mixer_invert() gets called. */
static void update_q_invert(sgpio_config_t* const config)
{
	/* 1=Output SGPIO11 High(TX mode), 0=Output SGPIO11 Low(RX mode) */
	bool tx_mode = (SGPIO_GPIO_OUTREG & (1 << 11)) > 0;

	/*
	 * This switch will need to change if we modify the CPLD to handle
	 * inversion the same way for RX and TX.
	 */
	bool baseband_invert = false;
	switch (detected_platform()) {
	case BOARD_ID_RAD1O:
	case BOARD_ID_HACKRF1_R9:
		baseband_invert = (tx_mode) ? false : true;
		break;
	default:
		baseband_invert = false;
	}

	gpio_write(config->gpio_q_invert, mixer_invert ^ baseband_invert);
}

void sgpio_cpld_set_mixer_invert(sgpio_config_t* const config, const uint_fast8_t invert)
{
	if (invert) {
		mixer_invert = true;
	} else {
		mixer_invert = false;
	}

	update_q_invert(config);
}
