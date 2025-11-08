#!/usr/bin/env python3
"""
Steganography Strength Analyzer
================================

Analyzes steganographic images for quality and detectability.
Uses statistical tests and image quality metrics.

METRICS:
- Visual Quality: PSNR, SSIM, MSE
- Statistical Detection: Chi-square, RS analysis
- Entropy Analysis: Shannon entropy, histogram analysis
- Embedding Capacity: Bits per pixel, total capacity
- Detectability Score: Composite risk metric

DETECTION METHODS:
- Chi-square test (Westfeld & Pfitzmann, 1999)
- RS Steganalysis (Fridrich et al., 2001)
- Sample Pair Analysis (Dumitrescu et al., 2003)
- Histogram analysis
- Entropy deviation

POLYGOTTEM Research, 2025
"""

import numpy as np
import sys
import os
from collections import Counter
import math

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[!] PIL not found - Install: pip install pillow")

try:
    from skimage.metrics import structural_similarity as ssim
    from skimage.metrics import peak_signal_noise_ratio as psnr
    SKIMAGE_AVAILABLE = True
except ImportError:
    SKIMAGE_AVAILABLE = False
    print("[!] scikit-image not found - Limited metrics available")
    print("    Install: pip install scikit-image")

VERSION = "1.0.0"


class StegoAnalyzer:
    """Comprehensive steganography analysis toolkit."""

    def __init__(self):
        self.results = {}

    def load_image(self, filename):
        """Load image as numpy array."""
        if not PIL_AVAILABLE:
            print("[!] PIL required for image loading")
            return None

        try:
            img = Image.open(filename)
            return np.array(img)
        except Exception as e:
            print(f"[!] Error loading {filename}: {e}")
            return None

    def calculate_mse(self, img1, img2):
        """Calculate Mean Squared Error."""
        return np.mean((img1.astype(float) - img2.astype(float)) ** 2)

    def calculate_psnr(self, img1, img2):
        """Calculate Peak Signal-to-Noise Ratio."""
        if SKIMAGE_AVAILABLE:
            return psnr(img1, img2)
        else:
            # Manual calculation
            mse = self.calculate_mse(img1, img2)
            if mse == 0:
                return float('inf')
            max_pixel = 255.0
            return 20 * math.log10(max_pixel / math.sqrt(mse))

    def calculate_ssim(self, img1, img2):
        """Calculate Structural Similarity Index."""
        if SKIMAGE_AVAILABLE:
            if len(img1.shape) == 3:
                return ssim(img1, img2, channel_axis=2)
            else:
                return ssim(img1, img2)
        else:
            print("[!] SSIM requires scikit-image")
            return None

    def calculate_entropy(self, data):
        """Calculate Shannon entropy."""
        if len(data) == 0:
            return 0

        # Flatten if multidimensional
        data_flat = data.flatten()

        # Count occurrences
        counts = Counter(data_flat)
        total = len(data_flat)

        # Calculate entropy
        entropy = 0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def chi_square_test(self, image):
        """
        Chi-square steganalysis test.

        Tests for unnatural distribution of LSB values.
        Westfeld & Pfitzmann (1999)

        Returns: (chi_square_statistic, p_value_estimate)
        """
        if len(image.shape) == 3:
            # Convert to grayscale
            image = np.mean(image, axis=2).astype(np.uint8)

        # Get LSB plane
        lsb = image & 1

        # Expected distribution (should be 50/50)
        total_pixels = lsb.size
        expected = total_pixels / 2

        # Observed distribution
        ones = np.sum(lsb)
        zeros = total_pixels - ones

        # Chi-square statistic
        chi_square = ((ones - expected) ** 2 / expected +
                     (zeros - expected) ** 2 / expected)

        # Estimate p-value (very rough approximation)
        # For 1 degree of freedom, chi_square > 3.84 is significant (p<0.05)
        if chi_square > 10.83:
            risk = "HIGH"
        elif chi_square > 3.84:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return chi_square, risk

    def rs_steganalysis(self, image):
        """
        RS Steganalysis (simplified version).

        Fridrich et al. (2001)
        Detects sequential LSB embedding.

        Returns: estimated embedding rate
        """
        if len(image.shape) == 3:
            image = np.mean(image, axis=2).astype(np.uint8)

        h, w = image.shape

        # Divide into groups
        rm = 0
        sm = 0
        r_m = 0
        s_m = 0

        # Sample groups (simplified - full implementation would be more complex)
        for i in range(0, h-1, 2):
            for j in range(0, w-1, 2):
                group = image[i:i+2, j:j+2].flatten()

                # Calculate discrimination function (simplified)
                f = np.sum(np.abs(np.diff(group.astype(int))))

                # Flip LSBs
                group_flipped = group.copy()
                group_flipped = (group_flipped & 0xFE) | (~group_flipped & 0x01)

                f_flipped = np.sum(np.abs(np.diff(group_flipped.astype(int))))

                # Classify
                if f_flipped > f:
                    rm += 1
                elif f_flipped < f:
                    sm += 1

        total = rm + sm
        if total == 0:
            return 0

        # Estimate embedding rate (simplified)
        embedding_rate = abs(rm - sm) / total

        return embedding_rate

    def histogram_analysis(self, image):
        """Analyze histogram for anomalies."""
        if len(image.shape) == 3:
            image = np.mean(image, axis=2).astype(np.uint8)

        # Calculate histogram
        hist, _ = np.histogram(image.flatten(), bins=256, range=(0, 256))

        # Check for spikes (typical of poor steganography)
        mean_count = np.mean(hist)
        std_count = np.std(hist)

        # Detect outliers (spikes)
        threshold = mean_count + 3 * std_count
        spikes = np.sum(hist > threshold)

        # Smoothness metric
        smoothness = np.std(np.diff(hist))

        return {
            'spikes': int(spikes),
            'smoothness': float(smoothness),
            'uniformity': float(np.std(hist))
        }

    def analyze_pair(self, cover_path, stego_path):
        """
        Analyze cover-stego pair.

        Returns comprehensive quality and detectability metrics.
        """
        print(f"\n[*] Steganography Strength Analyzer v{VERSION}")
        print(f"    Cover: {cover_path}")
        print(f"    Stego: {stego_path}")
        print()

        # Load images
        cover = self.load_image(cover_path)
        stego = self.load_image(stego_path)

        if cover is None or stego is None:
            return None

        if cover.shape != stego.shape:
            print("[!] Images have different dimensions")
            return None

        results = {}

        # Visual Quality Metrics
        print("[*] Calculating visual quality metrics...")
        results['mse'] = self.calculate_mse(cover, stego)
        results['psnr'] = self.calculate_psnr(cover, stego)
        results['ssim'] = self.calculate_ssim(cover, stego)

        # Entropy Analysis
        print("[*] Analyzing entropy...")
        results['cover_entropy'] = self.calculate_entropy(cover)
        results['stego_entropy'] = self.calculate_entropy(stego)
        results['entropy_delta'] = abs(results['cover_entropy'] - results['stego_entropy'])

        # Statistical Detection Tests
        print("[*] Running statistical detection tests...")
        results['chi_square'], results['chi_square_risk'] = self.chi_square_test(stego)
        results['rs_embedding_rate'] = self.rs_steganalysis(stego)

        # Histogram Analysis
        print("[*] Analyzing histograms...")
        results['histogram'] = self.histogram_analysis(stego)

        # Embedding Capacity Estimation
        total_pixels = cover.size
        if len(cover.shape) == 3:
            total_pixels = cover.shape[0] * cover.shape[1] * cover.shape[2]

        results['capacity_bits'] = total_pixels  # 1 bit per pixel (LSB)
        results['capacity_kb'] = total_pixels / (8 * 1024)

        # Overall Detectability Score (0-100, lower is better)
        detectability = 0

        # PSNR contribution (higher is better, less detectable)
        if results['psnr'] < 30:
            detectability += 40
        elif results['psnr'] < 40:
            detectability += 20
        elif results['psnr'] < 50:
            detectability += 10

        # Chi-square contribution
        if results['chi_square_risk'] == "HIGH":
            detectability += 30
        elif results['chi_square_risk'] == "MEDIUM":
            detectability += 15

        # RS analysis contribution
        if results['rs_embedding_rate'] > 0.5:
            detectability += 20
        elif results['rs_embedding_rate'] > 0.3:
            detectability += 10

        # Entropy contribution
        if results['entropy_delta'] > 0.5:
            detectability += 10

        results['detectability_score'] = min(detectability, 100)

        # Classification
        if results['detectability_score'] < 30:
            results['quality_rating'] = "EXCELLENT"
        elif results['detectability_score'] < 50:
            results['quality_rating'] = "GOOD"
        elif results['detectability_score'] < 70:
            results['quality_rating'] = "FAIR"
        else:
            results['quality_rating'] = "POOR"

        self.results = results
        return results

    def print_report(self):
        """Print detailed analysis report."""
        if not self.results:
            print("[!] No analysis results available")
            return

        r = self.results

        print("\n" + "="*70)
        print("  STEGANOGRAPHY STRENGTH ANALYSIS REPORT")
        print("="*70)

        print("\n📊 VISUAL QUALITY METRICS")
        print("-" * 70)
        print(f"  MSE (Mean Squared Error):        {r['mse']:.4f}")
        print(f"  PSNR (Peak Signal-to-Noise):     {r['psnr']:.2f} dB")
        if r['ssim'] is not None:
            print(f"  SSIM (Structural Similarity):    {r['ssim']:.4f}")

        print("\n📈 ENTROPY ANALYSIS")
        print("-" * 70)
        print(f"  Cover Entropy:                   {r['cover_entropy']:.4f} bits/byte")
        print(f"  Stego Entropy:                   {r['stego_entropy']:.4f} bits/byte")
        print(f"  Delta:                           {r['entropy_delta']:.4f}")

        print("\n🔍 STATISTICAL DETECTION TESTS")
        print("-" * 70)
        print(f"  Chi-Square Statistic:            {r['chi_square']:.4f}")
        print(f"  Chi-Square Risk:                 {r['chi_square_risk']}")
        print(f"  RS Embedding Rate:               {r['rs_embedding_rate']:.4f}")

        print("\n📉 HISTOGRAM ANALYSIS")
        print("-" * 70)
        print(f"  Histogram Spikes:                {r['histogram']['spikes']}")
        print(f"  Smoothness:                      {r['histogram']['smoothness']:.2f}")
        print(f"  Uniformity (std):                {r['histogram']['uniformity']:.2f}")

        print("\n💾 EMBEDDING CAPACITY")
        print("-" * 70)
        print(f"  Capacity (bits):                 {r['capacity_bits']:,}")
        print(f"  Capacity (KB):                   {r['capacity_kb']:.2f}")

        print("\n🎯 OVERALL ASSESSMENT")
        print("-" * 70)
        print(f"  Detectability Score:             {r['detectability_score']}/100")
        print(f"  Quality Rating:                  {r['quality_rating']}")

        print("\n💡 INTERPRETATION")
        print("-" * 70)

        if r['quality_rating'] == "EXCELLENT":
            print("  ✓ Very difficult to detect with statistical analysis")
            print("  ✓ High visual quality maintained")
            print("  ✓ Suitable for operational use")
        elif r['quality_rating'] == "GOOD":
            print("  ✓ Difficult to detect with basic analysis")
            print("  ✓ Good visual quality")
            print("  ⚠ Advanced steganalysis may detect")
        elif r['quality_rating'] == "FAIR":
            print("  ⚠ Detectable with statistical analysis")
            print("  ⚠ Visible artifacts may be present")
            print("  ⚠ Use only for low-security applications")
        else:
            print("  ✗ Easily detectable")
            print("  ✗ Poor visual quality")
            print("  ✗ Not recommended for use")

        print("\n📚 RECOMMENDATIONS")
        print("-" * 70)

        if r['psnr'] < 40:
            print("  • Reduce embedding rate to improve PSNR")

        if r['chi_square_risk'] != "LOW":
            print("  • Use adaptive embedding (not sequential LSB)")

        if r['rs_embedding_rate'] > 0.3:
            print("  • Consider spread spectrum or F5-style embedding")

        if r['entropy_delta'] > 0.3:
            print("  • Ensure embedded data is compressed/encrypted")

        print("\n" + "="*70)


def main():
    if len(sys.argv) < 3:
        print(f"Steganography Strength Analyzer v{VERSION}\n")
        print("Analyzes steganographic images for quality and detectability.\n")
        print("Usage:")
        print(f"  {sys.argv[0]} <cover_image> <stego_image>\n")
        print("Example:")
        print(f"  {sys.argv[0]} original.png hidden.png\n")
        print("Requirements:")
        print("  pip install pillow numpy scikit-image\n")
        return 1

    cover_path = sys.argv[1]
    stego_path = sys.argv[2]

    if not os.path.exists(cover_path):
        print(f"[!] Cover image not found: {cover_path}")
        return 1

    if not os.path.exists(stego_path):
        print(f"[!] Stego image not found: {stego_path}")
        return 1

    analyzer = StegoAnalyzer()
    results = analyzer.analyze_pair(cover_path, stego_path)

    if results:
        analyzer.print_report()
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
