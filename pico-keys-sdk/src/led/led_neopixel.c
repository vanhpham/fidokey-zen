/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "led/led.h"
#ifdef PICO_PLATFORM
#include "hardware/gpio.h"
#endif

#ifdef ESP_PLATFORM

#include "driver/gpio.h"
#include "neopixel.h"
#include <math.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif

tNeopixelContext neopixel = NULL;

tNeopixel pixel[] = {
    { 0, NP_RGB(0,  0,  0) }, /* off */
    { 0, NP_RGB(255,  0, 0) }, /* red */
    { 0, NP_RGB(0, 255,  0) }, /* green */
    { 0, NP_RGB(0, 0,  255) }, /* blue */
    { 0, NP_RGB(255,  255, 0) }, /* yellow */
    { 0, NP_RGB(255,  0, 255) }, /* magenta */
    { 0, NP_RGB(0, 255,  255) }, /* cyan */
    { 0, NP_RGB(255, 255,  255) }, /* white */
};

/* Base hue (in degrees) for each LED_COLOR_*, used by the gradient effect.
 * OFF and WHITE are unsaturated so their hue is irrelevant. */
static const float led_base_hue[] = {
    0.0f,   /* LED_COLOR_OFF (unused) */
    0.0f,   /* LED_COLOR_RED */
    120.0f, /* LED_COLOR_GREEN */
    240.0f, /* LED_COLOR_BLUE */
    60.0f,  /* LED_COLOR_YELLOW */
    300.0f, /* LED_COLOR_MAGENTA */
    180.0f, /* LED_COLOR_CYAN */
    0.0f,   /* LED_COLOR_WHITE (unused) */
};

#define LED_HUE_DRIFT_DEG   15.0f  /* how far the hue wanders around the base color; stays small so
                                     * it never reads as the neighboring color (60 deg apart) */

static void hsv_to_rgb(float h, float s, float v, uint8_t *r, uint8_t *g, uint8_t *b) {
    h = fmodf(h, 360.0f);
    if (h < 0) {
        h += 360.0f;
    }
    float c = v * s;
    float x = c * (1.0f - fabsf(fmodf(h / 60.0f, 2.0f) - 1.0f));
    float m = v - c;
    float rp = 0, gp = 0, bp = 0;
    if (h < 60) { rp = c; gp = x; bp = 0; }
    else if (h < 120) { rp = x; gp = c; bp = 0; }
    else if (h < 180) { rp = 0; gp = c; bp = x; }
    else if (h < 240) { rp = 0; gp = x; bp = c; }
    else if (h < 300) { rp = x; gp = 0; bp = c; }
    else { rp = c; gp = 0; bp = x; }
    *r = (uint8_t)roundf((rp + m) * 255.0f);
    *g = (uint8_t)roundf((gp + m) * 255.0f);
    *b = (uint8_t)roundf((bp + m) * 255.0f);
}

static inline uint32_t neopixel_rgb_ordered(uint8_t r, uint8_t g, uint8_t b) {
    switch (phy_data.led_order) {
        case PHY_LED_ORDER_RBG:
            return NP_RGB(r, b, g);
        case PHY_LED_ORDER_GRB:
            return NP_RGB(g, r, b);
        case PHY_LED_ORDER_GBR:
            return NP_RGB(g, b, r);
        case PHY_LED_ORDER_BRG:
            return NP_RGB(b, r, g);
        case PHY_LED_ORDER_BGR:
            return NP_RGB(b, g, r);
        case PHY_LED_ORDER_RGB:
        default:
            return NP_RGB(r, g, b);
    }
}

#if defined(CONFIG_IDF_TARGET_ESP32S3)
    #define NEOPIXEL_PIN GPIO_NUM_48
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #define NEOPIXEL_PIN GPIO_NUM_15
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    #define NEOPIXEL_PIN GPIO_NUM_8
#else
    #define NEOPIXEL_PIN GPIO_NUM_27
#endif

void led_driver_init_neopixel(void) {
    uint8_t gpio = NEOPIXEL_PIN;
    if (phy_data.led_gpio_present) {
        gpio = phy_data.led_gpio;
    }
    neopixel = neopixel_Init(1, gpio);
}

void led_driver_color_neopixel(uint8_t color, uint32_t led_brightness, float progress) {
    static tNeopixel spx = {.index = 0, .rgb = 0};

    if (color == LED_COLOR_OFF || led_brightness == 0) {
        spx.rgb = neopixel_rgb_ordered(0, 0, 0);
        neopixel_SetPixel(neopixel, &spx, 1);
        return;
    }

    /* Ease-in-out breathing curve instead of a hard on/off step, so the
     * pixel fades smoothly rather than blinking flatly. */
    float eased = 0.5f - 0.5f * cosf((float) M_PI * progress);

    uint32_t led_phy_btness = phy_data.led_brightness_present ? phy_data.led_brightness : MAX_BTNESS;
    float brightness = ((float)led_brightness / MAX_BTNESS) * ((float)led_phy_btness / MAX_BTNESS) * eased;

    /* Drift the hue in step with the same breathing cycle: it sits exactly
     * on the state's true color at the brightest point (progress == 0.5),
     * so the color is always unambiguous when the pixel is most visible,
     * and only wanders a little during the dim fade at the edges of the
     * cycle, giving a soft gradient glow there without hiding which state
     * this is. */
    float hue_drift = LED_HUE_DRIFT_DEG * cosf((float) M_PI * progress);
    float hue = led_base_hue[color] + hue_drift;
    float sat = (color == LED_COLOR_WHITE) ? 0.0f : 1.0f;

    uint8_t r, g, b;
    hsv_to_rgb(hue, sat, brightness, &r, &g, &b);

    spx.rgb = neopixel_rgb_ordered(r, g, b);
    neopixel_SetPixel(neopixel, &spx, 1);
}

led_driver_t led_driver_neopixel = {
    .init = led_driver_init_neopixel,
    .set_color = led_driver_color_neopixel,
};

#endif
