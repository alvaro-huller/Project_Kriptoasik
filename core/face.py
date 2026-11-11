"""Face recognition: YuNet (deteksi) + SFace (embedding) + cosine similarity + liveness gerak kepala."""
import os
import numpy as np
import cv2

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
YUNET = os.path.join(MODEL_DIR, "face_detection_yunet_2023mar.onnx")
SFACE = os.path.join(MODEL_DIR, "face_recognition_sface_2021dec.onnx")
COSINE_THRESHOLD = 0.363
YAW_RANGE_MIN = 0.30     # rentang gerak kepala (rasio) agar lolos liveness
MATCH_FRAMES_MIN = 8


class FaceEngine:
    def __init__(self):
        for p in (YUNET, SFACE):
            if not os.path.isfile(p):
                raise FileNotFoundError(f"Model hilang: {p}\nJalankan: python download_models.py")
        self.detector = cv2.FaceDetectorYN.create(YUNET, "", (320, 320), 0.9, 0.3, 5000)
        self.recognizer = cv2.FaceRecognizerSF.create(SFACE, "")

    def detect(self, frame):
        """Return baris wajah terbesar (15 nilai: bbox, 5 landmark, skor) atau None."""
        h, w = frame.shape[:2]
        self.detector.setInputSize((w, h))
        _, faces = self.detector.detect(frame)
        if faces is None or len(faces) == 0:
            return None
        return max(faces, key=lambda f: f[2] * f[3])

    def embed(self, frame, face) -> np.ndarray:
        aligned = self.recognizer.alignCrop(frame, face)
        return self.recognizer.feature(aligned).astype(np.float32).reshape(1, -1)

    def similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        return float(self.recognizer.match(a, b, cv2.FaceRecognizerSF_FR_COSINE))

    @staticmethod
    def yaw_proxy(face) -> float:
        """Posisi hidung relatif titik tengah mata, dinormalisasi jarak mata (proxy arah toleh)."""
        re, le, nose = face[4:6], face[6:8], face[8:10]
        eye_dist = max(abs(le[0] - re[0]), 1e-6)
        return float((nose[0] - (re[0] + le[0]) / 2) / eye_dist)


class Verifier:
    """Akumulasi frame: lolos jika cukup frame cocok DAN kepala bergerak (liveness)."""

    def __init__(self, engine: FaceEngine, template: np.ndarray):
        self.e, self.t = engine, template
        self.matched, self.yaws, self.last_sim = 0, [], 0.0

    def feed(self, frame):
        face = self.e.detect(frame)
        if face is None:
            return None, False
        self.last_sim = self.e.similarity(self.e.embed(frame, face), self.t)
        if self.last_sim >= COSINE_THRESHOLD:
            self.matched += 1
            self.yaws.append(self.e.yaw_proxy(face))
        return face, self.passed()

    def live(self) -> bool:
        return len(self.yaws) >= 2 and (max(self.yaws) - min(self.yaws)) >= YAW_RANGE_MIN

    def passed(self) -> bool:
        return self.matched >= MATCH_FRAMES_MIN and self.live()


def average_template(embs):
    m = np.mean(np.vstack(embs), axis=0, keepdims=True).astype(np.float32)
    return m / np.linalg.norm(m)
