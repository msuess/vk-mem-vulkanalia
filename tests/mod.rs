extern crate vulkanalia;
extern crate vk_mem_vulkanalia;

use vulkanalia::loader::{LibloadingLoader, LIBRARY};
use vulkanalia::prelude::v1_1::*;
use vulkanalia::vk::ExtDebugUtilsExtension;
use vulkanalia::Version;
use std::{os::raw::c_void, sync::Arc};
use vk_mem_vulkanalia::Alloc;

/// The Vulkan SDK version that started requiring the portability subset extension for macOS.
const PORTABILITY_MACOS_VERSION: Version = Version::new(1, 3, 216);

fn extension_names() -> Vec<*const i8> {
    vec![
        vk::EXT_DEBUG_UTILS_EXTENSION.name.as_ptr()
    ]
}

unsafe extern "system" fn vulkan_debug_callback(
    _message_severity: vk::DebugUtilsMessageSeverityFlagsEXT,
    _message_types: vk::DebugUtilsMessageTypeFlagsEXT,
    p_callback_data: *const vk::DebugUtilsMessengerCallbackDataEXT,
    _p_user_data: *mut c_void,
) -> vk::Bool32 {
    let p_callback_data = &*p_callback_data;
    println!(
        "{:?}",
        ::std::ffi::CStr::from_ptr(p_callback_data.message)
    );
    vk::FALSE
}

pub struct TestHarness {
    pub entry: Entry,
    pub instance: Instance,
    pub device: Device,
    pub physical_device: vk::PhysicalDevice,
    pub debug_callback: vk::DebugUtilsMessengerEXT,
    // pub debug_report_loader: debug_utils::Instance,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        unsafe {
            self.device.device_wait_idle().unwrap();
            self.device.destroy_device(None);
            self.instance.destroy_debug_utils_messenger_ext(self.debug_callback, None);
            self.instance.destroy_instance(None);
        }
    }
}
impl TestHarness {
    pub fn new() -> Self {
        let app_name = b"vk-mem-vulkanalia testing\0";
        let app_info = vk::ApplicationInfo::builder()
            .application_name(app_name)
            .application_version(0)
            .engine_name(app_name)
            .engine_version(0);

        let layer_names = [::std::ffi::CString::new("VK_LAYER_KHRONOS_validation").unwrap()];
        let layers_names_raw: Vec<*const i8> = layer_names
            .iter()
            .map(|raw_name| raw_name.as_ptr())
            .collect();

        let mut extension_names_raw = extension_names();
        // extension_names_raw.push(vk::KHR_MAINTENANCE4_EXTENSION.name.as_ptr());

        let loader = unsafe { LibloadingLoader::new(LIBRARY).unwrap() };
        let entry = unsafe { Entry::new(loader).unwrap() };

        let flags = if cfg!(target_os = "macos") && entry.version().unwrap() >= PORTABILITY_MACOS_VERSION {
            extension_names_raw.push(
                vk::KHR_GET_PHYSICAL_DEVICE_PROPERTIES2_EXTENSION
                    .name
                    .as_ptr(),
            );
            extension_names_raw.push(vk::KHR_PORTABILITY_ENUMERATION_EXTENSION.name.as_ptr());
            vk::InstanceCreateFlags::ENUMERATE_PORTABILITY_KHR
        } else {
            vk::InstanceCreateFlags::empty()
        };

        let instance_create_info = vk::InstanceCreateInfo::builder()
            .application_info(&app_info)
            .enabled_layer_names(&layers_names_raw)
            .enabled_extension_names(&extension_names_raw)
            .flags(flags);

        let instance = unsafe {
            entry
                .create_instance(&instance_create_info, None)
                .expect("Instance creation error")
        };

        let debug_info = vk::DebugUtilsMessengerCreateInfoEXT::builder()
            .message_severity(
                vk::DebugUtilsMessageSeverityFlagsEXT::ERROR
                    | vk::DebugUtilsMessageSeverityFlagsEXT::WARNING,
            )
            .message_type(
                vk::DebugUtilsMessageTypeFlagsEXT::GENERAL
                    | vk::DebugUtilsMessageTypeFlagsEXT::PERFORMANCE
                    | vk::DebugUtilsMessageTypeFlagsEXT::VALIDATION,
            )
            .user_callback(Some(vulkan_debug_callback));

        let debug_callback = unsafe {
            instance.create_debug_utils_messenger_ext(&debug_info, None).unwrap()
        };

        let physical_devices = unsafe {
            instance
                .enumerate_physical_devices()
                .expect("Physical device error")
        };

        // let physical_device = unsafe {
        //     *physical_devices
        //         .iter()
        //         .filter(|physical_device| {
        //             let version = instance
        //                 .get_physical_device_properties(**physical_device)
        //                 .api_version;
        //             print!("{}.{}", vk::version_major(version), vk::version_minor(version));
        //             vk::version_major(version) == 1
        //                 && vk::version_minor(version) == 0
        //         })
        //         .next()
        //         .expect("Couldn't find suitable device.")
        // };

        let physical_device = physical_devices[0];
        println!("sadfsadf ========================================================================");
        dbg!(physical_device);

        let priorities = [1.0];

        // instance.enumerate_device_extension_properties(physical_device, )

        let queue_info = [vk::DeviceQueueCreateInfo::builder()
            .queue_family_index(0)
            .queue_priorities(&priorities)];

        let mut device_extensions = vec![];
        if cfg!(target_os = "macos") && entry.version().unwrap() >= PORTABILITY_MACOS_VERSION {
            device_extensions.push(vk::KHR_PORTABILITY_SUBSET_EXTENSION.name.as_ptr());
        }

        // device_extensions.push(vk::KHR_DEDICATED_ALLOCATION_EXTENSION.name.as_ptr());

        let device_create_info = vk::DeviceCreateInfo::builder()
            .enabled_extension_names(&device_extensions)
            .queue_create_infos(&queue_info);

        let device: Device = unsafe {
            instance
                .create_device(physical_device, &device_create_info, None)
                .unwrap()
        };

        TestHarness {
            entry,
            instance,
            device,
            physical_device,
            // debug_report_loader,
            debug_callback,
        }
    }

    pub fn create_allocator(&self) -> vk_mem_vulkanalia::Allocator {
        let create_info =
            vk_mem_vulkanalia::AllocatorCreateInfo::new(
                &self.instance,
                &self.device,
                self.physical_device
            );
        unsafe {
            vk_mem_vulkanalia::Allocator::new(create_info).unwrap()
        }
    }
}

#[test]
fn create_harness() {
    let _ = TestHarness::new();
}

#[test]
fn create_allocator() {
    let harness = TestHarness::new();
    let _ = harness.create_allocator();
}

#[test]
fn create_gpu_buffer() {
    let harness = TestHarness::new();
    let allocator = harness.create_allocator();
    let allocation_info = vk_mem_vulkanalia::AllocationCreateInfo {
        usage: vk_mem_vulkanalia::MemoryUsage::Auto,
        ..Default::default()
    };

    unsafe {
        let (buffer, mut allocation) = allocator
            .create_buffer(
                &vk::BufferCreateInfo::builder().size(16 * 1024).usage(
                    vk::BufferUsageFlags::VERTEX_BUFFER
                        | vk::BufferUsageFlags::TRANSFER_DST,
                ),
                &allocation_info,
            )
            .unwrap();
        let allocation_info = allocator.get_allocation_info(&allocation);
        assert_eq!(allocation_info.mapped_data, std::ptr::null_mut());
        allocator.destroy_buffer(buffer, &mut allocation);
    }
}

#[test]
fn create_cpu_buffer_preferred() {
    let harness = TestHarness::new();
    let allocator = harness.create_allocator();
    let allocation_info = vk_mem_vulkanalia::AllocationCreateInfo {
        required_flags: vk::MemoryPropertyFlags::HOST_VISIBLE,
        preferred_flags: vk::MemoryPropertyFlags::HOST_COHERENT
            | vk::MemoryPropertyFlags::HOST_CACHED,
        flags: vk_mem_vulkanalia::AllocationCreateFlags::MAPPED,
        ..Default::default()
    };
    unsafe {
        let (buffer, mut allocation) = allocator
            .create_buffer(
                &vk::BufferCreateInfo::builder().size(16 * 1024).usage(
                    vk::BufferUsageFlags::VERTEX_BUFFER
                        | vk::BufferUsageFlags::TRANSFER_DST,
                ),
                &allocation_info,
            )
            .unwrap();
        let allocation_info = allocator.get_allocation_info(&allocation);
        assert_ne!(allocation_info.mapped_data, std::ptr::null_mut());
        allocator.destroy_buffer(buffer, &mut allocation);
    }
}

#[test]
fn create_gpu_buffer_pool() {
    let harness = TestHarness::new();
    let allocator = harness.create_allocator();
    let allocator = Arc::new(allocator);

    let buffer_info = vk::BufferCreateInfo::builder()
        .size(16 * 1024)
        .usage(vk::BufferUsageFlags::UNIFORM_BUFFER | vk::BufferUsageFlags::TRANSFER_DST);

    let allocation_info = vk_mem_vulkanalia::AllocationCreateInfo {
        required_flags: vk::MemoryPropertyFlags::HOST_VISIBLE,
        preferred_flags: vk::MemoryPropertyFlags::HOST_COHERENT
            | vk::MemoryPropertyFlags::HOST_CACHED,
        flags: vk_mem_vulkanalia::AllocationCreateFlags::MAPPED,

        ..Default::default()
    };
    unsafe {
        let memory_type_index = allocator
            .find_memory_type_index_for_buffer_info(&buffer_info, &allocation_info)
            .unwrap();

        // Create a pool that can have at most 2 blocks, 128 MiB each.
        let pool_info = vk_mem_vulkanalia::PoolCreateInfo {
            memory_type_index,
            block_size: 128 * 1024 * 1024,
            max_block_count: 2,
            ..Default::default()
        };

        let pool = allocator.create_pool(&pool_info).unwrap();

        let (buffer, mut allocation) = pool.create_buffer(&buffer_info, &allocation_info).unwrap();
        let allocation_info = allocator.get_allocation_info(&allocation);
        assert_ne!(allocation_info.mapped_data, std::ptr::null_mut());
        allocator.destroy_buffer(buffer, &mut allocation);
    }
}

#[test]
fn test_gpu_stats() {
    let harness = TestHarness::new();
    let allocator = harness.create_allocator();
    let allocation_info = vk_mem_vulkanalia::AllocationCreateInfo {
        usage: vk_mem_vulkanalia::MemoryUsage::Auto,
        ..Default::default()
    };

    unsafe {
        let stats_1 = allocator.calculate_statistics().unwrap();
        assert_eq!(stats_1.total.statistics.blockCount, 0);
        assert_eq!(stats_1.total.statistics.allocationCount, 0);
        assert_eq!(stats_1.total.statistics.allocationBytes, 0);

        let (buffer, mut allocation) = allocator
            .create_buffer(
                &vk::BufferCreateInfo::builder().size(16 * 1024).usage(
                    vk::BufferUsageFlags::VERTEX_BUFFER
                        | vk::BufferUsageFlags::TRANSFER_DST,
                ),
                &allocation_info,
            )
            .unwrap();

        let stats_2 = allocator.calculate_statistics().unwrap();
        assert_eq!(stats_2.total.statistics.blockCount, 1);
        assert_eq!(stats_2.total.statistics.allocationCount, 1);
        assert_eq!(stats_2.total.statistics.allocationBytes, 16 * 1024);

        allocator.destroy_buffer(buffer, &mut allocation);

        let stats_3 = allocator.calculate_statistics().unwrap();
        assert_eq!(stats_3.total.statistics.blockCount, 1);
        assert_eq!(stats_3.total.statistics.allocationCount, 0);
        assert_eq!(stats_3.total.statistics.allocationBytes, 0);
    }
}

#[test]
fn create_virtual_block() {
    let create_info = vk_mem_vulkanalia::VirtualBlockCreateInfo {
        size: 16 * 1024 * 1024,
        flags: vk_mem_vulkanalia::VirtualBlockCreateFlags::VMA_VIRTUAL_BLOCK_CREATE_LINEAR_ALGORITHM_BIT,
        allocation_callbacks: None,
    }; // 16MB block
    let _virtual_block =
        vk_mem_vulkanalia::VirtualBlock::new(create_info).expect("Couldn't create VirtualBlock");
}

#[test]
fn virtual_allocate_and_free() {
    let create_info = vk_mem_vulkanalia::VirtualBlockCreateInfo {
        size: 16 * 1024 * 1024,
        flags: vk_mem_vulkanalia::VirtualBlockCreateFlags::VMA_VIRTUAL_BLOCK_CREATE_LINEAR_ALGORITHM_BIT,
        allocation_callbacks: None,
    }; // 16MB block
    let mut virtual_block =
        vk_mem_vulkanalia::VirtualBlock::new(create_info).expect("Couldn't create VirtualBlock");

    let allocation_info = vk_mem_vulkanalia::VirtualAllocationCreateInfo {
        size: 8 * 1024 * 1024,
        alignment: 0,
        user_data: 0,
        flags: vk_mem_vulkanalia::VirtualAllocationCreateFlags::empty(),
    };

    // Fully allocate the VirtualBlock and then free both allocations
    unsafe {
        let (mut virtual_alloc_0, offset_0) = virtual_block.allocate(allocation_info).unwrap();
        let (mut virtual_alloc_1, offset_1) = virtual_block.allocate(allocation_info).unwrap();
        assert_ne!(offset_0, offset_1);
        virtual_block.free(&mut virtual_alloc_0);
        virtual_block.free(&mut virtual_alloc_1);
    }

    // Fully allocate it again and then clear it
    unsafe {
        let (_virtual_alloc_0, offset_0) = virtual_block.allocate(allocation_info).unwrap();
        let (_virtual_alloc_1, offset_1) = virtual_block.allocate(allocation_info).unwrap();
        assert_ne!(offset_0, offset_1);
        virtual_block.clear();
    }

    // VMA should trigger an assert when the VirtualBlock is dropped, if any
    // allocations have not been freed, or the block not cleared instead
}

#[test]
fn virtual_allocation_user_data() {
    let create_info = vk_mem_vulkanalia::VirtualBlockCreateInfo {
        size: 16 * 1024 * 1024,
        ..Default::default()
    }; // 16MB block
    let mut virtual_block =
        vk_mem_vulkanalia::VirtualBlock::new(create_info).expect("Couldn't create VirtualBlock");

    let user_data = Box::new(vec![12, 34, 56, 78, 90]);
    let allocation_info = vk_mem_vulkanalia::VirtualAllocationCreateInfo {
        size: 8 * 1024 * 1024,
        alignment: 0,
        user_data: user_data.as_ptr() as usize,
        flags: vk_mem_vulkanalia::VirtualAllocationCreateFlags::empty(),
    };

    unsafe {
        let (mut virtual_alloc_0, _) = virtual_block.allocate(allocation_info).unwrap();
        let queried_info = virtual_block
            .get_allocation_info(&virtual_alloc_0)
            .expect("Couldn't get VirtualAllocationInfo from VirtualBlock");
        let queried_user_data = std::slice::from_raw_parts(queried_info.user_data as *const i32, 5);
        assert_eq!(queried_user_data, &*user_data);
        virtual_block.free(&mut virtual_alloc_0);
    }
}

#[test]
fn virtual_block_out_of_space() {
    let create_info = vk_mem_vulkanalia::VirtualBlockCreateInfo {
        size: 16 * 1024 * 1024,
        ..Default::default()
    }; // 16MB block
    let mut virtual_block =
        vk_mem_vulkanalia::VirtualBlock::new(create_info).expect("Couldn't create VirtualBlock");

    let allocation_info = vk_mem_vulkanalia::VirtualAllocationCreateInfo {
        size: 16 * 1024 * 1024 + 1,
        alignment: 0,
        user_data: 0,
        flags: vk_mem_vulkanalia::VirtualAllocationCreateFlags::empty(),
    };

    unsafe {
        match virtual_block.allocate(allocation_info) {
            Ok(_) => panic!("Created VirtualAllocation larger than VirtualBlock"),
            Err(vk::ErrorCode::OUT_OF_DEVICE_MEMORY) => {}
            Err(_) => panic!("Unexpected VirtualBlock error"),
        }
    }
}
