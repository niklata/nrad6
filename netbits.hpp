#ifndef NK_NRAD6_NETBITS_HPP_
#define NK_NRAD6_NETBITS_HPP_

#include <stdint.h>

static inline void encode32be(uint32_t v, uint8_t *dest)
{
    dest[0] = v >> 24;
    dest[1] = (v >> 16) & 0xff;
    dest[2] = (v >> 8) & 0xff;
    dest[3] = v & 0xff;
}

static inline void encode16be(uint16_t v, uint8_t *dest)
{
    dest[0] = v >> 8;
    dest[1] = v & 0xff;
}

static inline uint32_t decode32be(const uint8_t *src)
{
    return (static_cast<uint32_t>(src[0]) << 24)
         | ((static_cast<uint32_t>(src[1]) << 16) & 0xff0000)
         | ((static_cast<uint32_t>(src[2]) << 8) & 0xff00)
         | (static_cast<uint32_t>(src[3]) & 0xff);
}

static inline uint16_t decode16be(const uint8_t *src)
{
    return (static_cast<uint16_t>(src[0]) << 8)
         | (static_cast<uint16_t>(src[1]) & 0xff);
}

static inline void toggle_bit(bool v, uint8_t *data,
                              std::size_t arrayidx, uint32_t bitidx)
{
    if (v)
        data[arrayidx] |= bitidx;
    else
        data[arrayidx] &= ~bitidx;
}

#endif

