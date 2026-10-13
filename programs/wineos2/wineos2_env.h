/*
 *  wineos2_env.h - OS/2 Environment Subsystem Simulation Layout
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#ifndef __WINE_WINEOS2_ENV_H
#define __WINE_WINEOS2_ENV_H

#include <stdint.h>

/* 
 * Sets up the dynamic flat environment metrics and retrieves 
 * the 32-bit Process Information Block (PIB) simulation address.
 */
int wineos2_setup_lx_environment(uint32_t* out_pib_ptr);

#endif /* __WINE_WINEOS2_ENV_H */
