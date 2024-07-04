/*
 * Copyright 2022 Great Scott Gadgets <info@greatscottgadgets.com>
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

#include "platform_detect.h"
#include "firmware_info.h"
#include "gpio_lpc.h"
#include "hackrf_core.h"

#include <libopencm3/lpc43xx/scu.h>
#include <libopencm3/lpc43xx/adc.h>

static board_id_t platform = BOARD_ID_UNDETECTED;
static board_rev_t revision = BOARD_REV_UNDETECTED;

static struct gpio_t gpio2_9_on_P5_0 = GPIO(2, 9);
static struct gpio_t gpio3_6_on_P6_10 = GPIO(3, 6);

#define P5_0_PUP  (1 << 0)
#define P5_0_PDN  (1 << 1)
#define P6_10_PUP (1 << 2)
#define P6_10_PDN (1 << 3)

/*
 * Jawbreaker has a pull-down on P6_10 and nothing on P5_0.
 * rad1o has a pull-down on P6_10 and a pull-down on P5_0.
 * HackRF One OG has a pull-down on P6_10 and a pull-up on P5_0.
 * HackRF One r9 has a pull-up on P6_10 and a pull-down on P5_0.
 */

#define JAWBREAKER_RESISTORS (P6_10_PDN)
#define RAD1O_RESISTORS      (P6_10_PDN | P5_0_PDN)
#define HACKRF1_OG_RESISTORS (P6_10_PDN | P5_0_PUP)
#define HACKRF1_R9_RESISTORS (P6_10_PUP | P5_0_PDN)

/*
 * LEDs are configured so that they flash if the detected hardware platform is
 * not supported by the firmware binary. Only two LEDs are flashed for a
 * hardware detection failure, but three LEDs are flashed if CPLD configuration
 * fails.
 */
static struct gpio_t gpio_led1 = GPIO(2, 1);
static struct gpio_t gpio_led2 = GPIO(2, 2);
static struct gpio_t gpio_led3 = GPIO(2, 8);

/*
 * Return 10-bit ADC result.
 */
uint16_t adc_read(uint8_t pin)
{
	pin &= 0x7;
	uint8_t pin_mask = (1 << pin);
	ADC0_CR = ADC_CR_SEL(pin_mask) | ADC_CR_CLKDIV(45) | ADC_CR_PDN | ADC_CR_START(1);
	while (!(ADC0_GDR & ADC_DR_DONE) || (((ADC0_GDR >> 24) & 0x7) != pin)) {}
	return (ADC0_GDR >> 6) & 0x03FF;
}

void adc_off(void)
{
	ADC0_CR = 0;
}

/*
 * Starting with r6, HackRF One has pin straps on ADC pins that indicate
 * hardware revision. Those pins were unconnected prior to r6, so we test for
 * the unconnected state by averaging several ADC readings.
 */
#define NUM_SAMPLES    (10)
#define LOW_THRESHOLD  (2)
#define HIGH_THRESHOLD (1022)

#define HIGH(x)   ((x) > HIGH_THRESHOLD)
#define LOW(x)    ((x) < LOW_THRESHOLD)
#define ABSENT(x) (((x) >= LOW_THRESHOLD) && ((x) <= HIGH_THRESHOLD))

uint32_t check_pin_strap(uint8_t pin)
{
	int i;
	uint32_t sum = 0;

	for (i = 0; i < NUM_SAMPLES; i++) {
		sum += adc_read(pin);
	}
	adc_off();
	return (sum / NUM_SAMPLES);
}

/*
 * Starting with r10, HackRF One uses a voltage divider on ADC0_3 to set an
 * analog voltage that indicates the hardware revision. The high five bits of
 * the ADC result are mapped to 32 revisions. HackRF One r8 also fits into this
 * scheme with ADC0_3 tied to VCC.
 */
// clang-format off
static const uint8_t revision_from_adc[32] = {
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_UNRECOGNIZED,
	BOARD_REV_HACKRF1_R10,
	BOARD_REV_HACKRF1_R8
};

// clang-format on

void detect_hardware_platform(void)
{
	uint8_t detected_resistors = 0;

	scu_pinmux(SCU_PINMUX_LED2, SCU_GPIO_NOPULL | SCU_CONF_FUNCTION0);
	scu_pinmux(SCU_PINMUX_LED3, SCU_GPIO_NOPULL | SCU_CONF_FUNCTION0);
	gpio_input(&gpio_led1);
	gpio_output(&gpio_led2);
	gpio_output(&gpio_led3);

	gpio_input(&gpio2_9_on_P5_0);
	gpio_input(&gpio3_6_on_P6_10);

	/* activate internal pull-down */
	scu_pinmux(P5_0, SCU_GPIO_PDN | SCU_CONF_FUNCTION0);
	scu_pinmux(P6_10, SCU_GPIO_PDN | SCU_CONF_FUNCTION0);
	delay_us_at_mhz(4, 96);
	/* tri-state for a moment before testing input */
	scu_pinmux(P5_0, SCU_GPIO_NOPULL | SCU_CONF_FUNCTION0);
	scu_pinmux(P6_10, SCU_GPIO_NOPULL | SCU_CONF_FUNCTION0);
	delay_us_at_mhz(4, 96);
	/* if input rose quickly, there must be an external pull-up */
	detected_resistors |= (gpio_read(&gpio2_9_on_P5_0)) ? P5_0_PUP : 0;
	detected_resistors |= (gpio_read(&gpio3_6_on_P6_10)) ? P6_10_PUP : 0;

	/* activate internal pull-up */
	scu_pinmux(P5_0, SCU_GPIO_PUP | SCU_CONF_FUNCTION0);
	scu_pinmux(P6_10, SCU_GPIO_PUP | SCU_CONF_FUNCTION0);
	delay_us_at_mhz(4, 96);
	/* tri-state for a moment before testing input */
	scu_pinmux(P5_0, SCU_GPIO_NOPULL | SCU_CONF_FUNCTION0);
	scu_pinmux(P6_10, SCU_GPIO_NOPULL | SCU_CONF_FUNCTION0);
	delay_us_at_mhz(4, 96);
	/* if input fell quickly, there must be an external pull-down */
	detected_resistors |= (gpio_read(&gpio2_9_on_P5_0)) ? 0 : P5_0_PDN;
	detected_resistors |= (gpio_read(&gpio3_6_on_P6_10)) ? 0 : P6_10_PDN;

	switch (detected_resistors) {
	case JAWBREAKER_RESISTORS:
		if (!(supported_platform() & PLATFORM_JAWBREAKER)) {
			halt_and_flash(3000000);
		}
		platform = BOARD_ID_JAWBREAKER;
		return;
	case RAD1O_RESISTORS:
		if (!(supported_platform() & PLATFORM_RAD1O)) {
			halt_and_flash(3000000);
		}
		platform = BOARD_ID_RAD1O;
		return;
	case HACKRF1_OG_RESISTORS:
		if (!(supported_platform() & PLATFORM_HACKRF1_OG)) {
			halt_and_flash(3000000);
		}
		platform = BOARD_ID_HACKRF1_OG;
		break;
	case HACKRF1_R9_RESISTORS:
		if (!(supported_platform() & PLATFORM_HACKRF1_R9)) {
			halt_and_flash(3000000);
		}
		platform = BOARD_ID_HACKRF1_R9;
		break;
	default:
		platform = BOARD_ID_UNRECOGNIZED;
		halt_and_flash(1000000);
	}

	uint32_t adc0_3 = check_pin_strap(3);
	uint32_t adc0_4 = check_pin_strap(4);
	uint32_t adc0_7 = check_pin_strap(7);

	if (platform == BOARD_ID_HACKRF1_OG) {
		if (ABSENT(adc0_3) && ABSENT(adc0_4) && ABSENT(adc0_7)) {
			revision = BOARD_REV_HACKRF1_OLD;
		} else if (HIGH(adc0_3) && HIGH(adc0_4)) {
			revision = BOARD_REV_HACKRF1_R6;
		} else if (LOW(adc0_3) && HIGH(adc0_4)) {
			revision = BOARD_REV_HACKRF1_R7;
		} else if (LOW(adc0_4)) {
			revision = revision_from_adc[adc0_3 >> 5];
		} else {
			revision = BOARD_REV_UNRECOGNIZED;
		}
	} else if (platform == BOARD_ID_HACKRF1_R9) {
		if (LOW(adc0_3) && LOW(adc0_4)) {
			revision = BOARD_REV_HACKRF1_R9;
		} else {
			revision = BOARD_REV_UNRECOGNIZED;
		}
	}

	if ((revision > BOARD_REV_HACKRF1_OLD) && LOW(adc0_7)) {
		revision |= BOARD_REV_GSG;
	}
}

board_id_t detected_platform(void)
{
	return platform;
}

board_rev_t detected_revision(void)
{
	return revision;
}

uint32_t supported_platform(void)
{
	return firmware_info.supported_platform;
}
