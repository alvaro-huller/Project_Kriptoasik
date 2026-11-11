"""Unduh model YuNet + SFace dari OpenCV Zoo ke folder models/."""
import os, urllib.request
BASE = "https://github.com/opencv/opencv_zoo/raw/main/models/"
FILES = {
    "face_detection_yunet_2023mar.onnx": BASE + "face_detection_yunet/face_detection_yunet_2023mar.onnx",
    "face_recognition_sface_2021dec.onnx": BASE + "face_recognition_sface/face_recognition_sface_2021dec.onnx",
}
d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(d, exist_ok=True)
for name, url in FILES.items():
    p = os.path.join(d, name)
    if os.path.exists(p):
        print("ada:", name); continue
    print("unduh:", name)
    urllib.request.urlretrieve(url, p)
print("selesai")
