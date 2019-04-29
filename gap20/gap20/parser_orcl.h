#pragma once

uint8_t *fast_ensure_contiguous(uint8_t *input, const uint32_t input_len, const uint32_t offset, const uint32_t length);
uint8_t tvb_get_uint8(uint8_t * input, const uint32_t input_len, const uint32_t offset);
void dumpbin(char *name, const uint8_t *buff, size_t len);

