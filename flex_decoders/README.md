# Flex Decoders

Place custom rtl_433 flex decoder `.conf` files in this directory.
They will be automatically loaded when the capture tool starts.

## How to create a flex decoder

1. Run the capture tool and look for unknown signal detections
2. Analyze the pulse timing data from the unknown signals
3. Write a `.conf` file following the rtl_433 flex decoder format
4. Restart the capture tool to load it

## Example flex decoder format

```
# My custom TPMS sensor
decoder {
    name        = Custom-TPMS,
    modulation  = FSK_PCM,
    short       = 52,
    long        = 52,
    gap         = 0,
    reset       = 150,
    preamble    = {24}0xaaa,
    bits        = 68,
    get         = id:@0:{32},
    get         = pressure_kPa:@32:{8}:[0:400],
    get         = temperature_C:@40:{8}:[-40:215],
    get         = flags:@48:{8},
}
```

## Resources

- [rtl_433 flex decoder docs](https://github.com/merbanan/rtl_433/blob/master/docs/FLEX_DECODER.md)
- [Community decoder examples](https://github.com/merbanan/rtl_433/tree/master/conf)
