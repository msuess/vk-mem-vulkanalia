use vulkanalia::VkResult;
use vulkanalia::vk;

pub fn to_vk_result(result: vk::Result) -> VkResult<()> {
    match result {
        vk::Result::SUCCESS => Ok(()),
        error => Err(error.into()),
    }
}
