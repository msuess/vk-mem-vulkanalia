# vk-mem-vulkanalia

[![Latest version](https://img.shields.io/crates/v/vk-mem-vulkanalia.svg)](https://crates.io/crates/vk-mem-vulkanalia)
[![Documentation](https://docs.rs/vk-mem/badge.svg)](https://docs.rs/vk-mem-vulkanalia)
![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![APACHE2](https://img.shields.io/badge/license-APACHE2-blue.svg)

This crate is a fork of [vk-mem](https://crates.io/crates/vk-mem) using [vulkanalia](https://crates.io/crates/vulkanalia) instead of [ash](https://crates.io/crates/ash). It provides an FFI layer and idiomatic rust wrappers for the excellent AMD Vulkan Memory Allocator (VMA) C/C++ library.

- [Documentation](https://docs.rs/vk-mem-vulkanalia)
- [Release Notes](https://github.com/msuess/vk-mem-vulkanalia/releases)
- [vk-mem GitHub](https://github.com/gwihlidal/vk-mem-rs)
- [VMA GitHub](https://github.com/GPUOpen-LibrariesAndSDKs/VulkanMemoryAllocator)
- [VMA Documentation](https://gpuopen-librariesandsdks.github.io/VulkanMemoryAllocator/html/)
- [GPU Open Announce](https://gpuopen.com/gaming-product/vulkan-memory-allocator/)
- [GPU Open Update](https://gpuopen.com/vulkan-memory-allocator-2-3-0/)

## Problem

Memory allocation and resource (buffer and image) creation in Vulkan is difficult (comparing to older graphics API-s, like D3D11 or OpenGL) for several reasons:

- It requires a lot of boilerplate code, just like everything else in Vulkan, because it is a low-level and high-performance API.
- There is additional level of indirection: VkDeviceMemory is allocated separately from creating VkBuffer/VkImage and they must be bound together. The binding cannot be changed later - resource must be recreated.
- Driver must be queried for supported memory heaps and memory types. Different IHVs provide different types of it.
- It is recommended practice to allocate bigger chunks of memory and assign parts of them to particular resources.

## Features

This crate can help game developers to manage memory allocations and resource creation by offering some higher-level functions:

- Functions that help to choose correct and optimal memory type based on intended usage of the memory.
  - Required or preferred traits of the memory are expressed using higher-level description comparing to Vulkan flags.
- Functions that allocate memory blocks, reserve and return parts of them (VkDeviceMemory + offset + size) to the user.
  - Library keeps track of allocated memory blocks, used and unused ranges inside them, finds best matching unused ranges for new allocations, respects all the rules of alignment and buffer/image granularity.
- Functions that can create an image/buffer, allocate memory for it and bind them together - all in one call.

Additional features:

- Cross-platform
  - Windows
  - Linux
  - macOS (MoltenVK)
- Well tested and documented API
  - Underlying library ships in a number of commerical game titles.
  - Extensive documentation (including full algorithm descriptions in the VMA repository)
- Support for custom memory pools:
  - Create a pool with desired parameters (e.g. fixed or limited maximum size)
  - Allocate memory out of it.
  - Support for a linear or buddy allocation strategy
  - Create a pool with linear algorithm and use it for much faster allocations and deallocations in free-at-once, stack, double stack, or ring buffer fashion.
- Detailed statistics:
  - Globally, per memory heap, and per memory type.
  - Amount of memory used
  - Amount of memory unused
  - Number of allocated blocks
  - Number of allocations
  - etc.
- Debug annotations:
  - Associate string with name or opaque pointer to your own data with every allocation.
- JSON dump:
  - Obtain a string in JSON format with detailed map of internal state, including list of allocations and gaps between them.
  - Convert this JSON dump into a picture to visualize your memory. See [tools/VmaDumpVis](https://github.com/GPUOpen-LibrariesAndSDKs/VulkanMemoryAllocator/blob/master/tools/VmaDumpVis/README.md).
- Support for memory mapping:
  - Reference-counted internally.
  - Support for persistently mapped memory; just allocate with appropriate flag and you get access to mapped pointer.
- Support for defragmenting allocations:
  - Call one function and let the library move data around to free some memory blocks and make your allocations better compacted.
- Support for lost allocations:
  - Allocate memory with appropriate flags and let the library remove allocations that are not used for many frames to make room for new ones.
- Support for non-coherent memory and flushing allocations:
  - `nonCoherentAtomSize` is respected automatically.
- Supporting for attempting to detect incorrect mapped memory usage:
  - Enable initialization of all allocated memory with a bit pattern to detect usage of uninitialized or freed memory.
  - Enable validation of a magic number before and after every allocation to detect out-of-bounds memory corruption.

## Planned Features

- Extensive unit tests and examples.
  - Some unit tests already, but not full coverage
  - Example isn't written - likely will port the VMA sample to `vulkanalia` and `vk_mem_vulkanalia`
- Record and replay allocations, for in-depth analysis of memory usage, resource transitions, etc
  - Check for correctness, measure performance, and gather statistics.

## Example

Basic usage of this crate is very simple; advanced features are optional.

After you create a `vk_mem_vulkanalia::Allocator` instance, very little code is needed to create a buffer:

```rust
// Create the buffer (GPU only, 16KiB in this example)
let create_info = vk_mem_vulkanalia::AllocationCreateInfo {
    usage: vk_mem_vulkanalia::MemoryUsage::GpuOnly,
    ..Default::default()
};

let (buffer, allocation, allocation_info) = allocator
    .create_buffer(
        &vulkanalia::vk::BufferCreateInfo::builder()
            .size(16 * 1024)
            .usage(vulkanalia::vk::BufferUsageFlags::VERTEX_BUFFER | vulkanalia::vk::BufferUsageFlags::TRANSFER_DST),
        &create_info,
    )
    .unwrap();

// Do stuff with buffer! (type is vulkanalia::vk::Buffer)

// Destroy the buffer
allocator.destroy_buffer(buffer, &allocation).unwrap();
```

With this one function call (`vk_mem::Allocator::create_buffer`):

- `vulkanalia::vk::Buffer` (`VkBuffer`) is created.
- `vulkanalia::vk::DeviceMemory` (`VkDeviceMemory`) block is allocated if needed.
- An unused region of the memory block is bound to this buffer.
- `vk_mem_vulkanalia::Allocation` is created that represents memory assigned to this buffer. It can be queried for parameters like Vulkan memory handle and offset.

## MoltenVK

For MoltenVK on macOS, you need to have the proper environment variables set. Something like:

```bash
export SDK_PATH=/path/to/vulkansdk-macos-1.1.106.0
export DYLD_LIBRARY_PATH=$SDK_PATH/macOS/lib
export VK_ICD_FILENAMES=$SDK_PATH/macOS/etc/vulkan/icd.d/MoltenVK_icd.json
export VK_LAYER_PATH=$SDK_PATH/macOS/etc/vulkan/explicit_layer.d
cargo test
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
vk-mem-vulkanalia = "0.1.0+vk-mem-0.4.0"
```

and add this to your crate root:

```rust
extern crate vk_mem_vulkanalia;
```

## Compiling using MinGW W64

Vulkan Memory Allocator requires C++11 threads.
MinGW W64 does not support these by default, so you need to switch to the posix build.
For example, on debian you need to run the following:

```bash
update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
update-alternatives --set i686-w64-mingw32-gcc /usr/bin/i686-w64-mingw32-gcc-posix
update-alternatives --set i686-w64-mingw32-g++ /usr/bin/i686-w64-mingw32-g++-posix
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Credits and Special Thanks

- [Adam Sawicki - AMD](https://github.com/adam-sawicki-amd) (Author of C/C++ library)
- [Kyle Mayes](https://github.com/KyleMayes) (Author of vulkanalia - Vulkan rust bindings)
- [Graham Wihlidal](https://github.com/gwihlidal) (Author of vk-mem)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

Contributions are always welcome; please look at the [issue tracker](https://github.com/msuess/vk-mem-vulkanalia/issues) to see what known improvements are documented.

## Code of Conduct

Contribution to the vk-mem-vulkanalia crate is organized under the terms of the
Contributor Covenant, the maintainer of vk-mem-vulkanalia, @msuess, promises to
intervene to uphold that code of conduct.
