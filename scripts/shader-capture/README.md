# SPIR-V capture experiment

This is an opt-in diagnostic. A normal build omits `metal2vulkan-runtime`'s
`shader-capture` feature entirely. A diagnostic build must explicitly enable
that Cargo feature and start the target process with
`METAL2VULKAN_CAPTURE_SPIRV=1`. The optional
`METAL2VULKAN_CAPTURE_SPIRV_START` selects a zero-based four-stage window;
invalid values disable capture. The window counts stages observed while
creating variant objects, not GPU invocations. Cache hits and compilation
order can change which stages appear.

The runtime queues up to four SPIR-V modules of at most 32 KiB each to a
bounded background worker. It does not write a file, change the shader,
create a cache, or change a Vulkan return value. A full queue, failed worker
creation, invalid or oversized module causes a silent drop. The worker emits framed records through an optional registered callback, or
writes them to stderr when no callback is registered. The a04br3 diagnostic
constructor registers the existing `native_metal_board_text` transport and
fragments each record into lines at most 63 characters long. Delivery of a
complete shader through that route has not been tested on the device. A
process can exit before flushing, and diagnostic CPU and logging can perturb
timing. Do not enable the feature in distributable images by default.

Pass a log from exactly one boot to `python3 scripts/shader-capture/decode.py
<log> <new-host-output-directory>`. The decoder refuses missing, duplicated,
interleaved incorrectly, truncated or corrupted records, validates the
SHA-256, and writes SPIR-V plus a manifest on the host. Shader data is private
input and is not to be committed. The PID and ordinal do not distinguish
boots by themselves; the caller must segment the log first.

These records contain the stage, entry point and exact module bytes only. They
do not capture descriptor layouts, pipeline specialization, attachment and
raster state, device features, compiler build identity, or the PCO IR. They
cannot alone replay a pipeline or establish which module caused the sampled
PC hotspot. A real comparison needs the relevant pipeline state and matching
device/compiler configuration, plus output and GPU execution validation.
