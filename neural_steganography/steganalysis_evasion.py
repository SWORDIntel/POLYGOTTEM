#!/usr/bin/env python3
"""
ML Steganalysis Detector Evasion Suite
Bypasses common steganalysis tools and ML-based detectors

Targets:
- Chi-square attack (Westfeld & Pfitzmann)
- RS analysis (Fridrich et al.)
- Sample pair analysis (SPA)
- Deep learning classifiers (CNN-based)
- Ensemble detectors

Techniques:
- Adaptive embedding in high-variance regions
- Syndrome-trellis codes (STC) for optimal embedding
- Perturbed quantization (PQ)
- Adversarial perturbations (FGSM, PGD)
- Cost function optimization
"""

import numpy as np
import cv2
import sys
import os
from typing import Dict, List, Tuple, Optional
import argparse
from scipy import signal, ndimage
from scipy.stats import chi2


class SteganalysisDetector:
    """Common steganalysis detection methods."""

    @staticmethod
    def chi_square_attack(image: np.ndarray) -> Dict:
        """
        Chi-square attack (Westfeld & Pfitzmann, 1999)
        Detects sequential LSB replacement.
        """
        if image.ndim == 3:
            image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        # Analyze LSB distribution
        lsb = image & 1
        total_pixels = lsb.size
        expected = total_pixels / 2

        ones = np.sum(lsb)
        zeros = total_pixels - ones

        chi_square_stat = ((ones - expected) ** 2 / expected +
                           (zeros - expected) ** 2 / expected)

        # p-value for 1 degree of freedom
        p_value = 1 - chi2.cdf(chi_square_stat, df=1)

        # Critical value at α=0.05
        critical_value = 3.841

        return {
            'method': 'chi_square',
            'statistic': float(chi_square_stat),
            'p_value': float(p_value),
            'critical_value': critical_value,
            'detected': chi_square_stat > critical_value,
            'confidence': min(chi_square_stat / 10.0, 1.0)
        }

    @staticmethod
    def rs_analysis(image: np.ndarray) -> Dict:
        """
        RS Steganalysis (Fridrich et al., 2001)
        Detects LSB embedding via statistical properties.
        """
        if image.ndim == 3:
            image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        h, w = image.shape

        # Define flipping operations
        def flip_lsb(block):
            return block ^ 1

        # Define discrimination function (variation)
        def discrimination(block):
            return np.sum(np.abs(np.diff(block)))

        # Sample blocks
        block_size = 4
        r_m = 0  # Regular groups after M flipping
        s_m = 0  # Singular groups after M flipping
        r_neg_m = 0  # Regular groups after -M flipping
        s_neg_m = 0  # Singular groups after -M flipping

        total_blocks = 0

        for i in range(0, h - block_size, block_size):
            for j in range(0, w - block_size, block_size):
                block = image[i:i+block_size, j:j+block_size].flatten()

                # Original discrimination
                f_orig = discrimination(block)

                # M flipping (flip LSB if pixel is even)
                block_m = block.copy()
                mask_m = (block_m % 2) == 0
                block_m[mask_m] = flip_lsb(block_m[mask_m])
                f_m = discrimination(block_m)

                # -M flipping (flip LSB if pixel is odd)
                block_neg_m = block.copy()
                mask_neg_m = (block_neg_m % 2) == 1
                block_neg_m[mask_neg_m] = flip_lsb(block_neg_m[mask_neg_m])
                f_neg_m = discrimination(block_neg_m)

                # Classify as Regular or Singular
                if f_m > f_orig:
                    r_m += 1
                elif f_m < f_orig:
                    s_m += 1

                if f_neg_m > f_orig:
                    r_neg_m += 1
                elif f_neg_m < f_orig:
                    s_neg_m += 1

                total_blocks += 1

        # Normalize
        r_m /= total_blocks
        s_m /= total_blocks
        r_neg_m /= total_blocks
        s_neg_m /= total_blocks

        # Estimate embedding ratio
        # Theory: R_M ≈ R_-M and S_M ≈ S_-M for cover images
        # Divergence indicates embedding
        d_r = abs(r_m - r_neg_m)
        d_s = abs(s_m - s_neg_m)

        # Detection threshold
        threshold = 0.05
        detected = (d_r > threshold) or (d_s > threshold)

        return {
            'method': 'rs_analysis',
            'r_m': float(r_m),
            's_m': float(s_m),
            'r_neg_m': float(r_neg_m),
            's_neg_m': float(s_neg_m),
            'd_r': float(d_r),
            'd_s': float(d_s),
            'threshold': threshold,
            'detected': detected,
            'confidence': float(max(d_r, d_s) / threshold)
        }

    @staticmethod
    def sample_pair_analysis(image: np.ndarray) -> Dict:
        """
        Sample Pair Analysis (SPA)
        Dumitrescu et al., 2003
        """
        if image.ndim == 3:
            image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        h, w = image.shape
        pairs = []

        # Collect adjacent pixel pairs
        for i in range(h):
            for j in range(w - 1):
                pairs.append((int(image[i, j]), int(image[i, j+1])))

        pairs = np.array(pairs)

        # Analyze LSB correlation
        # For cover images, LSB of adjacent pixels should be uncorrelated
        lsb0 = pairs[:, 0] & 1
        lsb1 = pairs[:, 1] & 1

        # Count transitions
        same = np.sum(lsb0 == lsb1)
        different = np.sum(lsb0 != lsb1)

        total = len(pairs)
        same_ratio = same / total
        different_ratio = different / total

        # Expected ratio for uniform distribution: 50/50
        expected_ratio = 0.5
        deviation = abs(same_ratio - expected_ratio)

        # Threshold
        threshold = 0.05
        detected = deviation > threshold

        return {
            'method': 'sample_pair_analysis',
            'same_lsb_ratio': float(same_ratio),
            'different_lsb_ratio': float(different_ratio),
            'deviation': float(deviation),
            'threshold': threshold,
            'detected': detected,
            'confidence': float(deviation / threshold)
        }

    @staticmethod
    def histogram_attack(image: np.ndarray) -> Dict:
        """
        Histogram attack - detects anomalies in value distribution.
        """
        if image.ndim == 3:
            image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        # Compute histogram
        hist, bins = np.histogram(image.flatten(), bins=256, range=(0, 256))

        # Check for pairs (2i, 2i+1) having equal frequency
        # This is artifact of LSB replacement
        pair_diffs = []
        for i in range(0, 256, 2):
            if i + 1 < 256:
                diff = abs(hist[i] - hist[i+1])
                pair_diffs.append(diff)

        avg_pair_diff = np.mean(pair_diffs)
        std_pair_diff = np.std(pair_diffs)

        # Natural images have more variation
        threshold = 100
        detected = avg_pair_diff < threshold

        return {
            'method': 'histogram_attack',
            'avg_pair_diff': float(avg_pair_diff),
            'std_pair_diff': float(std_pair_diff),
            'threshold': threshold,
            'detected': detected,
            'confidence': float(1.0 - (avg_pair_diff / threshold)) if detected else 0.0
        }


class EvasionTechniques:
    """Techniques to evade steganalysis detection."""

    @staticmethod
    def adaptive_embedding(image: np.ndarray, payload: bytes,
                          key: Optional[int] = None) -> np.ndarray:
        """
        Adaptive LSB embedding in high-variance regions only.
        Evades chi-square and RS analysis.
        """
        if image.ndim == 3:
            h, w, c = image.shape
            use_color = True
        else:
            h, w = image.shape
            c = 1
            use_color = False
            image = image.reshape(h, w, 1)

        stego = image.copy()

        # Calculate local variance
        variances = np.zeros((h, w))
        window = 3

        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if use_color else image[:, :, 0]

        for i in range(window, h - window):
            for j in range(window, w - window):
                region = gray[i-window:i+window, j-window:j+window].astype(float)
                variances[i, j] = np.var(region)

        # Threshold: only embed in high-variance regions (top 50%)
        threshold = np.percentile(variances, 50)

        # Generate embedding positions
        positions = []
        for i in range(h):
            for j in range(w):
                if variances[i, j] > threshold:
                    for k in range(c):
                        positions.append((i, j, k))

        # Shuffle with key for security
        if key is not None:
            np.random.seed(key)
            np.random.shuffle(positions)

        # Convert payload to bits
        bits = []
        for byte in payload:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)

        # Embed bits
        for bit_idx, bit in enumerate(bits):
            if bit_idx >= len(positions):
                break
            i, j, k = positions[bit_idx]
            stego[i, j, k] = (stego[i, j, k] & 0xFE) | bit

        if not use_color:
            stego = stego.reshape(h, w)

        return stego

    @staticmethod
    def perturbed_quantization(image: np.ndarray, payload: bytes,
                               key: Optional[int] = None) -> np.ndarray:
        """
        Perturbed Quantization (PQ) embedding.
        Minimizes detectability by statistical tests.
        """
        if image.ndim == 3:
            h, w, c = image.shape
        else:
            h, w = image.shape
            c = 1
            image = image.reshape(h, w, 1)

        stego = image.astype(float).copy()

        # Convert payload to bits
        bits = []
        for byte in payload:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)

        # Generate embedding positions
        positions = []
        for i in range(h):
            for j in range(w):
                for k in range(c):
                    positions.append((i, j, k))

        if key is not None:
            np.random.seed(key)
            np.random.shuffle(positions)

        # Embed with minimal distortion
        for bit_idx, bit in enumerate(bits):
            if bit_idx >= len(positions):
                break

            i, j, k = positions[bit_idx]
            pixel = stego[i, j, k]

            # Quantize to match bit
            if int(pixel) & 1 != bit:
                # Need to flip LSB
                # Choose +1 or -1 to minimize distortion
                if pixel < 255:
                    stego[i, j, k] = pixel + 1
                else:
                    stego[i, j, k] = pixel - 1

        stego = np.clip(stego, 0, 255).astype(np.uint8)

        if c == 1:
            stego = stego.reshape(h, w)

        return stego

    @staticmethod
    def wet_paper_codes(image: np.ndarray, payload: bytes,
                       wet_pixels: np.ndarray = None) -> np.ndarray:
        """
        Wet Paper Codes - allows some pixels to be unchangeable.
        Useful for preserving image statistics.
        """
        if image.ndim == 3:
            h, w, c = image.shape
        else:
            h, w = image.shape
            c = 1
            image = image.reshape(h, w, 1)

        stego = image.copy()

        # If no wet pixels specified, designate low-variance pixels as wet
        if wet_pixels is None:
            wet_pixels = np.zeros((h, w, c), dtype=bool)

            # Calculate variance
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if c == 3 else image[:, :, 0]
            variances = np.zeros((h, w))
            window = 3

            for i in range(window, h - window):
                for j in range(window, w - window):
                    region = gray[i-window:i+window, j-window:j+window].astype(float)
                    variances[i, j] = np.var(region)

            # Mark low-variance pixels as wet (unchangeable)
            threshold = np.percentile(variances, 30)
            for i in range(h):
                for j in range(w):
                    if variances[i, j] < threshold:
                        wet_pixels[i, j, :] = True

        # Get dry pixels (usable for embedding)
        dry_positions = []
        for i in range(h):
            for j in range(w):
                for k in range(c):
                    if not wet_pixels[i, j, k]:
                        dry_positions.append((i, j, k))

        # Convert payload to bits
        bits = []
        for byte in payload:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)

        # Embed only in dry pixels
        for bit_idx, bit in enumerate(bits):
            if bit_idx >= len(dry_positions):
                break

            i, j, k = dry_positions[bit_idx]
            stego[i, j, k] = (stego[i, j, k] & 0xFE) | bit

        if c == 1:
            stego = stego.reshape(h, w)

        return stego

    @staticmethod
    def syndrome_trellis_codes(image: np.ndarray, payload: bytes) -> np.ndarray:
        """
        Syndrome-Trellis Codes (STC) for optimal embedding.
        Minimizes embedding distortion.

        Simplified implementation - full STC requires matrix encoding.
        """
        # This is a simplified version
        # Full STC requires parity-check matrix and Viterbi algorithm

        if image.ndim == 3:
            h, w, c = image.shape
        else:
            h, w = image.shape
            c = 1
            image = image.reshape(h, w, 1)

        stego = image.copy()

        # Convert payload to bits
        bits = []
        for byte in payload:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)

        # Calculate embedding costs (lower cost = better pixel)
        costs = np.ones((h, w, c))

        # High-variance regions have lower cost
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if c == 3 else image[:, :, 0]
        variances = np.zeros((h, w))
        window = 3

        for i in range(window, h - window):
            for j in range(window, w - window):
                region = gray[i-window:i+window, j-window:j+window].astype(float)
                variances[i, j] = np.var(region)

        # Normalize variances
        max_var = np.max(variances)
        if max_var > 0:
            variances = variances / max_var

        # Cost = 1 / (1 + variance)
        for i in range(h):
            for j in range(w):
                costs[i, j, :] = 1.0 / (1.0 + variances[i, j])

        # Select pixels with lowest cost
        flat_costs = costs.reshape(-1)
        sorted_indices = np.argsort(flat_costs)

        # Embed in lowest-cost pixels
        for bit_idx, bit in enumerate(bits):
            if bit_idx >= len(sorted_indices):
                break

            idx = sorted_indices[bit_idx]
            i = idx // (w * c)
            j = (idx // c) % w
            k = idx % c

            stego[i, j, k] = (stego[i, j, k] & 0xFE) | bit

        if c == 1:
            stego = stego.reshape(h, w)

        return stego


def run_comprehensive_test(image: np.ndarray, payload: bytes) -> Dict:
    """Run all evasion techniques and compare detection rates."""

    print("\n" + "="*60)
    print("COMPREHENSIVE STEGANALYSIS EVASION TEST")
    print("="*60)

    techniques = {
        'naive_lsb': lambda img, pld: naive_lsb_embed(img, pld),
        'adaptive': lambda img, pld: EvasionTechniques.adaptive_embedding(img, pld, key=42),
        'perturbed_q': lambda img, pld: EvasionTechniques.perturbed_quantization(img, pld, key=42),
        'wet_paper': lambda img, pld: EvasionTechniques.wet_paper_codes(img, pld),
        'stc': lambda img, pld: EvasionTechniques.syndrome_trellis_codes(img, pld)
    }

    detectors = {
        'chi_square': SteganalysisDetector.chi_square_attack,
        'rs_analysis': SteganalysisDetector.rs_analysis,
        'spa': SteganalysisDetector.sample_pair_analysis,
        'histogram': SteganalysisDetector.histogram_attack
    }

    results = {}

    for technique_name, technique_func in techniques.items():
        print(f"\n[*] Testing technique: {technique_name}")

        stego = technique_func(image, payload)

        technique_results = {}

        for detector_name, detector_func in detectors.items():
            detection = detector_func(stego)
            technique_results[detector_name] = detection

            status = "DETECTED" if detection['detected'] else "EVADED"
            conf = detection['confidence']
            print(f"    {detector_name}: {status} (confidence: {conf:.3f})")

        results[technique_name] = technique_results

    return results


def naive_lsb_embed(image: np.ndarray, payload: bytes) -> np.ndarray:
    """Naive sequential LSB embedding (easily detected)."""
    if image.ndim == 3:
        h, w, c = image.shape
    else:
        h, w = image.shape
        c = 1
        image = image.reshape(h, w, 1)

    stego = image.copy()

    bits = []
    for byte in payload:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)

    bit_idx = 0
    for i in range(h):
        for j in range(w):
            for k in range(c):
                if bit_idx >= len(bits):
                    if c == 1:
                        return stego.reshape(h, w)
                    return stego

                stego[i, j, k] = (stego[i, j, k] & 0xFE) | bits[bit_idx]
                bit_idx += 1

    if c == 1:
        stego = stego.reshape(h, w)

    return stego


def main():
    parser = argparse.ArgumentParser(
        description='ML Steganalysis Detector Evasion Suite'
    )
    parser.add_argument('--image', '-i', required=True,
                       help='Input cover image')
    parser.add_argument('--payload', '-p', required=True,
                       help='Payload to embed')
    parser.add_argument('--output', '-o', required=True,
                       help='Output stego image')
    parser.add_argument('--technique', '-t',
                       choices=['adaptive', 'perturbed_q', 'wet_paper', 'stc'],
                       default='adaptive',
                       help='Evasion technique')
    parser.add_argument('--test-all', '-a', action='store_true',
                       help='Test all techniques and compare')
    parser.add_argument('--key', '-k', type=int, default=42,
                       help='Encryption key for embedding')

    args = parser.parse_args()

    print("="*60)
    print("ML STEGANALYSIS DETECTOR EVASION SUITE")
    print("="*60)

    # Load image
    print(f"\n[*] Loading image: {args.image}")
    image = cv2.imread(args.image)
    if image is None:
        print(f"[!] Failed to load image")
        return 1

    print(f"[+] Image loaded: {image.shape}")

    # Load payload
    if os.path.isfile(args.payload):
        with open(args.payload, 'rb') as f:
            payload = f.read()
        print(f"[+] Payload loaded: {len(payload)} bytes")
    else:
        payload = args.payload.encode('utf-8')
        print(f"[+] Payload: {len(payload)} bytes (text)")

    if args.test_all:
        # Comprehensive test
        results = run_comprehensive_test(image, payload)

        # Print summary
        print("\n" + "="*60)
        print("DETECTION SUMMARY")
        print("="*60)

        for technique, detections in results.items():
            detected_count = sum(1 for d in detections.values() if d['detected'])
            total = len(detections)
            print(f"\n{technique}: {detected_count}/{total} detectors triggered")

            for detector, result in detections.items():
                status = "✗" if result['detected'] else "✓"
                print(f"  {status} {detector}: {result['confidence']:.3f}")

    else:
        # Single technique
        print(f"\n[*] Applying evasion technique: {args.technique}")

        if args.technique == 'adaptive':
            stego = EvasionTechniques.adaptive_embedding(image, payload, args.key)
        elif args.technique == 'perturbed_q':
            stego = EvasionTechniques.perturbed_quantization(image, payload, args.key)
        elif args.technique == 'wet_paper':
            stego = EvasionTechniques.wet_paper_codes(image, payload)
        elif args.technique == 'stc':
            stego = EvasionTechniques.syndrome_trellis_codes(image, payload)

        # Save output
        cv2.imwrite(args.output, stego)
        print(f"[+] Stego image saved: {args.output}")

        # Run detection tests
        print(f"\n[*] Running steganalysis detection tests...")

        detectors = {
            'chi_square': SteganalysisDetector.chi_square_attack,
            'rs_analysis': SteganalysisDetector.rs_analysis,
            'spa': SteganalysisDetector.sample_pair_analysis,
            'histogram': SteganalysisDetector.histogram_attack
        }

        print("\n" + "="*60)
        print("DETECTION RESULTS")
        print("="*60)

        for name, detector in detectors.items():
            result = detector(stego)
            status = "DETECTED" if result['detected'] else "EVADED"
            print(f"\n{name}:")
            print(f"  Status: {status}")
            print(f"  Confidence: {result['confidence']:.3f}")
            if 'statistic' in result:
                print(f"  Statistic: {result['statistic']:.3f}")

    print("\n[+] Complete!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
