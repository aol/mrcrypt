import pytest

from mrcrypt import algorithms


@pytest.mark.parametrize('algorithm_id, expected_algorithm', [
    (0x0014, algorithms.alg_aes_128_gcm_iv12_tag16_no_kdf),
    (0x0046, algorithms.alg_aes_192_gcm_iv12_tag16_no_kdf),
    (0x0078, algorithms.alg_aes_256_gcm_iv12_tag16_no_kdf),
    (0x0114, algorithms.alg_aes_128_gcm_iv12_tag16_hkdf_sha256),
    (0x0146, algorithms.alg_aes_192_gcm_iv12_tag16_hkdf_sha256),
    (0x0178, algorithms.alg_aes_256_gcm_iv12_tag16_hkdf_sha256),
    (0x0214, algorithms.alg_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256),
    (0x0346, algorithms.alg_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384),
    (0x0378, algorithms.alg_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384),
])
def test_algorithm_from_id(algorithm_id, expected_algorithm):
    algorithm = algorithms.algorithm_from_id(algorithm_id)

    assert algorithm == expected_algorithm


@pytest.mark.parametrize('algorithm_id', [0x0000])
def test_algorithm_from_id__invalid_id(algorithm_id):
    with pytest.raises(ValueError):
        algorithms.algorithm_from_id(algorithm_id)


def test_default_algorithm():
    result = algorithms.default_algorithm()

    assert isinstance(result, algorithms.AlgorithmProfile)
