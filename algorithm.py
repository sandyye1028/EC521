#导入所需的库
import cv2
import numpy as np
from gmssl import sm9
from sklearn.cluster import KMeans
from scipy.spatial.distance import cosine

#创建一个名为SimpleBiometricLibrary的类，其中包含一个名为extract_features的静态方法，用于提取指纹图像的特征。
class SimpleBiometricLibrary:
    @staticmethod
    def extract_features(image_path):
        ## 以灰度模式读取图像
        image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        # 使用ORB特征提取器提取特征
        
        orb = cv2.ORB_create(nfeatures=500)
        keypoints, descriptors = orb.detectAndCompute(image, None)

        # 使用KMeans聚类对特征进行聚类以获得固定长度的输出
        kmeans = KMeans(n_clusters=32)
        kmeans.fit(descriptors)
        histogram, _ = np.histogram(kmeans.labels_, bins=32, range=(0, 32))

        # 重塑直方图以适应所需的格式
        if len(histogram.shape) == 1:
            histogram = histogram.reshape(-1, 1)
        elif histogram.shape[0] == 1:
            histogram = histogram.reshape(1, -1)

        return histogram

#函数生成密钥对和指纹的特征向量
def keygen(user_id, fingerprint_image_path):
    master_public, master_secret = sm9.setup('sign')
    private_key = sm9.private_key_extract('sign', master_public, master_secret, user_id)

    # 提取指纹特征
    enrollment_features = SimpleBiometricLibrary.extract_features(fingerprint_image_path)

    return master_public, private_key, enrollment_features


#函数使用SM9签名算法对消息进行签名
def sign(master_public, private_key, message):
    signature = sm9.sign(master_public, private_key, message)
    return signature

def verify(master_public, user_id, enrollment_features, fingerprint_image_path, message, signature):
    is_valid = sm9.verify(master_public, user_id, message, signature)

    if not is_valid:
        return False

    verification_features = SimpleBiometricLibrary.extract_features(fingerprint_image_path)

    # 计算enrollment_features和verification_features之间的余弦相似度
    cosine_similarity = 1 - cosine(enrollment_features.flatten(), verification_features.flatten())

    # 设置阈值以确定签名是否有效
    
    return cosine_similarity > 0.9






if __name__ == "__main__":
    user_id = "Alice"
    enrollment_fingerprint_image_path = "/home/sunci/Pictures/103_5.tif"

    master_public, private_key, enrollment_features = keygen(user_id, enrollment_fingerprint_image_path)
    message = "Hello, world!"
    signature = sign(master_public, private_key, message)

    verification_fingerprint_image_path = "/home/sunci/Pictures/103_6.tif"
    is_valid = verify(master_public, user_id, enrollment_features, verification_fingerprint_image_path, message, signature)

    if is_valid:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")


