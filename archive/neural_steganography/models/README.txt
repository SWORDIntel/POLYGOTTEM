GAN-Based Steganography Training Pipeline
==========================================

This implementation requires:
- PyTorch: pip install torch torchvision
- OpenVINO (optional): pip install openvino

For hardware acceleration on Intel NPU/GNA/ARC (130+ TOPS):
- Install OpenVINO toolkit
- Use AUTO device selector for automatic hardware selection

Architecture:
1. Generator: Embeds secret data into cover images
2. Discriminator: Distinguishes stego from cover images
3. Extractor: Recovers secret from stego images

Training Pipeline:
- Adversarial training (GAN)
- Perceptual loss for visual quality
- Extraction loss for recoverability

Export to OpenVINO:
- ONNX intermediate format
- OpenVINO IR for deployment
- NPU/GNA inference support

Run with:
python3 gan_steg_trainer.py

To install dependencies:
pip install torch torchvision openvino pillow numpy
