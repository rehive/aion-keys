from typing import Tuple  # noqa: F401


#
# SECPK1N
#
SECPK1_P = 2**256 - 2**32 - 977  # type: int
SECPK1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337  # type: int  # noqa: E501
SECPK1_A = 0  # type: int  # noqa: E501
SECPK1_B = 7  # type: int  # noqa: E501
SECPK1_Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240  # type: int  # noqa: E501
SECPK1_Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424  # type: int  # noqa: E501
SECPK1_G = (SECPK1_Gx, SECPK1_Gy)  # type: Tuple[int, int]


#
# ED25519
#
ED25519_BITS = 256
ED25519_AION_BITS = 128
ED25519_Q = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_Dnum = -121665
ED25519_Dden = 121666
