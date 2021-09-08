from charm.toolbox.eccurve import prime192v1
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.core.engine.util import objectToBytes,bytesToObject
 

from hashlib import sha256


import sys
import json
import base64

def p(x, coeff_list):
    return ((coeff_list[0] * x) + coeff_list[1])


def egcd(a, b):
    '''
        Extended Euclidian gcd function between a and b
    '''
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    '''
        Finding modulo inverse of a mod m
    '''
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def testcharm(invar):
#    print("received: " + str(invar))
    return 22

#Setup
def setup():
    #Setting EC
    group = PairingGroup('SS512')

    g1 = group.random(G1)
    g2 = group.random(G2)
    q = group.order()
    e_g1g2 = pair(g1, g2)

    #user GIDs
    u1 = group.random(ZR)
    u2 = group.random(ZR)
    u3 = group.random(ZR)

    #Attributes 1,2,3,4, represented with ai where i is the index used in polynomials
    #a1,a2,a3,a4

    #Secret between Auth1 and Auth2
    s_12 = group.random(ZR)

    #Secret between Auth2 and Auth3
    s_23 = group.random(ZR)

    #Secret between Auth1 and Auth3
    s_13 = group.random(ZR)

    #MPK/MSK Authority 1
    v_1 = group.random(ZR)
    Y_1 = (e_g1g2) ** v_1
    x_1 = group.random(ZR)
    y_1 = g1 ** x_1
    #Attr computation
    t_1a1 = group.random(ZR)
    T_1a1 = g2 ** t_1a1
    t_1a2 = group.random(ZR)
    T_1a2 = g2 ** t_1a2
    t_1a3 = group.random(ZR)
    T_1a3 = g2 ** t_1a3
    t_1a4 = group.random(ZR)
    T_1a4 = g2 ** t_1a4

    #MPK/MSK Authority 2
    v_2 = group.random(ZR)
    Y_2 = (e_g1g2) ** v_2
    x_2 = group.random(ZR)
    y_2 = g1 ** x_2
    #Attr computation
    t_2a1 = group.random(ZR)
    T_2a1 = g2 ** t_2a1
    t_2a2 = group.random(ZR)
    T_2a2 = g2 ** t_2a2
    t_2a3 = group.random(ZR)
    T_2a3 = g2 ** t_2a3
    t_2a4 = group.random(ZR)
    T_2a4 = g2 ** t_2a4
    
    #MPK/MSK Authority 3
    v_3 = group.random(ZR)
    Y_3 = (e_g1g2) ** v_3
    x_3 = group.random(ZR)
    y_3 = g1 ** x_3
    #Attr computation
    t_3a1 = group.random(ZR)
    T_3a1 = g2 ** t_3a1
    t_3a2 = group.random(ZR)
    T_3a2 = g2 ** t_3a2
    t_3a3 = group.random(ZR)
    T_3a3 = g2 ** t_3a3
    t_3a4 = group.random(ZR)
    T_3a4 = g2 ** t_3a4

    #Auth1 and Auth2
    PRF_12_u1 = y_1 ** (x_2 * (1 / (s_12 + u1)))
    PRF_12_u2 = y_1 ** (x_2 * (1 / (s_12 + u2)))
    PRF_12_u3 = y_1 ** (x_2 * (1 / (s_12 + u3)))

    #Auth2 and Auth3
    PRF_23_u1 = y_2 ** (x_3 * (1 / (s_23 + u1)))
    PRF_23_u2 = y_2 ** (x_3 * (1 / (s_23 + u2)))
    PRF_23_u3 = y_2 ** (x_3 * (1 / (s_23 + u3)))

    #Auth1 and Auth3
    PRF_13_u1 = y_1 ** (x_3 * (1 / (s_13 + u1)))
    PRF_13_u2 = y_1 ** (x_3 * (1 / (s_13 + u2)))
    PRF_13_u3 = y_1 ** (x_3 * (1 / (s_13 + u3)))


    #All Authorities compute
    Y = Y_1 * Y_2 * Y_3

    #authorities also give NIZKP of v_k and x_k

    #Auth1 stores
    MSK_1 = (x_1, (s_12, s_13), (t_1a1, t_1a2, t_1a3, t_1a4))

    #Auth2 stores
    MSK_2 = (x_2, (s_12, s_23), (t_2a1, t_2a2, t_2a3, t_2a4))

    #Auth3 stores
    MSK_3 = (x_3, (s_13, s_23), (t_3a1, t_3a2, t_3a3, t_3a4))


    #system params published,
    params = (Y, ((y_1, T_1a1, T_1a2, T_1a3, T_1a4), (y_2, T_2a1, T_2a2, T_2a3, T_2a4), (y_3, T_3a1, T_3a2, T_3a3, T_3a4)))




    ########KEY ISSUING############
    #USER SIGNUP
    #u1 signup
    #with auth1, k=1
    #auth2, j=2
    g = y_2 ** x_1
    h = g1
    R_12_u1 = group.random(ZR)
    #since k(1) > j(2) ? is false
    gamma_1 = delta_12 = -1
    alpha_1 = delta_12 * R_12_u1
    beta_1 = s_12
    #since  k(1) < j(2),
    D_12_u1 = (g1 ** R_12_u1) * (1 / PRF_12_u1)
    #D_12_u1 sent to user

    #auth3, j=3
    g = y_3 ** x_1
    h = g1
    R_13_u1 = group.random(ZR)
    #since k(1) > j(3) ? is false
    gamma_1 = delta_13 = -1
    alpha_1 = delta_13 * R_13_u1
    beta_1 = s_13
    #since  k(1) < j(3),
    D_13_u1 = (g1 ** R_13_u1) * (1 / PRF_13_u1)
    #D_13_u1 sent to user


    #with auth2, k=2
    #auth1, j=1
    g = y_1 ** x_2
    h = g1
    R_21_u1 = group.random(ZR)
    #since k(2) > j(1) ? is true
    gamma_2 = delta_21 = 1
    alpha_2 = delta_21 * R_21_u1
    beta_2 = s_12
    #since  k(2) > j(1),
    D_21_u1 = (g1 ** R_21_u1) * PRF_12_u1
    #D_21_u1 sent to user

    #auth3, j=3
    g = y_3 ** x_2
    h = g1
    R_23_u1 = group.random(ZR)
    #since k(2) > j(3) ? is false
    gamma_2 = delta_23 = -1
    alpha_2 = delta_23 * R_23_u1
    beta_2 = s_23
    #since  k(2) < j(3),
    D_23_u1 = (g1 ** R_23_u1) * (1 / PRF_23_u1)
    #D_23_u1 sent to user


    #with auth3, k=3
    #auth2, j=2
    g = y_2 ** x_3
    h = g1
    R_32_u1 = group.random(ZR)
    #since k(3) > j(2) ? is true
    gamma_3 = delta_32 = 1
    alpha_3 = delta_32 * R_32_u1
    beta_3 = s_23
    #since  k(3) > j(2),
    D_32_u1 = (g1 ** R_32_u1) * PRF_23_u1
    #D_32_u1 sent to user

    #auth1, j=1
    g = y_1 ** x_3
    h = g1
    R_31_u1 = group.random(ZR)
    #since k(3) > j(1) ? is true
    gamma_3 = delta_31 = 1
    alpha_3 = delta_31 * R_31_u1
    beta_3 = s_13
    #since  k(3) > j(1),
    D_31_u1 = (g1 ** R_31_u1) * PRF_13_u1
    #D_31_u1 sent to user


    #u2 signup
    #with auth1, k=1
    #auth2, j=2
    g = y_2 ** x_1
    h = g1
    R_12_u2 = group.random(ZR)
    #since k(1) > j(2) ? is false
    gamma_1 = delta_12 = -1
    alpha_1 = delta_12 * R_12_u2
    beta_1 = s_12
    #since  k(1) < j(2),
    D_12_u2 = (g1 ** R_12_u2) * (1 / PRF_12_u2)
    #D_12_u2 sent to user

    #auth3, j=3
    g = y_3 ** x_1
    h = g1
    R_13_u2 = group.random(ZR)
    #since k(1) > j(3) ? is false
    gamma_1 = delta_13 = -1
    alpha_1 = delta_13 * R_13_u2
    beta_1 = s_13
    #since  k(1) < j(3),
    D_13_u2 = (g1 ** R_13_u2) * (1 / PRF_13_u2)
    #D_13_u2 sent to user

    #with auth2, k=2
    #auth1, j=1
    g = y_1 ** x_2
    h = g1
    R_21_u2 = group.random(ZR)
    #since k(2) > j(1) ? is true
    gamma_2 = delta_21 = 1
    alpha_2 = delta_21 * R_21_u2
    beta_2 = s_12
    #since  k(2) > j(1),
    D_21_u2 = (g1 ** R_21_u2) * PRF_12_u2
    #D_21_u2 sent to user

    #auth3, j=3
    g = y_3 ** x_2
    h = g1
    R_23_u2 = group.random(ZR)
    #since k(2) > j(3) ? is false
    gamma_2 = delta_23 = -1
    alpha_2 = delta_23 * R_23_u2
    beta_2 = s_23
    #since  k(2) < j(3),
    D_23_u2 = (g1 ** R_23_u2) * (1 / PRF_23_u2)
    #D_23_u2 sent to user


    #with auth3, k=3
    #auth2, j=2
    g = y_2 ** x_3
    h = g1
    R_32_u2 = group.random(ZR)
    #since k(3) > j(2) ? is true
    gamma_3 = delta_32 = 1
    alpha_3 = delta_32 * R_32_u2
    beta_3 = s_23
    #since  k(3) > j(2),
    D_32_u2 = (g1 ** R_32_u2) * PRF_23_u2
    #D_32_u2 sent to user

    #auth3, j=1
    g = y_1 ** x_3
    h = g1
    R_31_u2 = group.random(ZR)
    #since k(3) > j(1) ? is true
    gamma_3 = delta_31 = 1
    alpha_3 = delta_31 * R_31_u2
    beta_3 = s_13
    #since  k(3) > j(1),
    D_31_u2 = (g1 ** R_31_u2) * PRF_13_u2
    #D_31_u2 sent to user





    #u3 signup
    #with auth1, k=1
    #auth2, j=2
    g = y_2 ** x_1
    h = g1
    R_12_u3 = group.random(ZR)
    #since k(1) > j(2) ? is false
    gamma_1 = delta_12 = -1
    alpha_1 = delta_12 * R_12_u3
    beta_1 = s_12
    #since  k(1) < j(2),
    D_12_u3 = (g1 ** R_12_u3) * (1 / PRF_12_u3)
    #D_12_u2 sent to user

    #auth3, j=3
    g = y_3 ** x_1
    h = g1
    R_13_u3 = group.random(ZR)
    #since k(1) > j(3) ? is false
    gamma_1 = delta_13 = -1
    alpha_1 = delta_13 * R_13_u3
    beta_1 = s_13
    #since  k(1) < j(3),
    D_13_u3 = (g1 ** R_13_u3) * (1 / PRF_13_u3)
    #D_13_u2 sent to user



    #with auth2, k=2
    #auth1, j=1
    g = y_1 ** x_2
    h = g1
    R_21_u3 = group.random(ZR)
    #since k(2) > j(1) ? is true
    gamma_2 = delta_21 = 1
    alpha_2 = delta_21 * R_21_u3
    beta_2 = s_12
    #since  k(2) > j(1),
    D_21_u3 = (g1 ** R_21_u3) * PRF_12_u3
    #D_21_u2 sent to user

    #auth3, j=3
    g = y_3 ** x_2
    h = g1
    R_23_u3 = group.random(ZR)
    #since k(2) > j(3) ? is false
    gamma_2 = delta_23 = -1
    alpha_2 = delta_23 * R_23_u3
    beta_2 = s_23
    #since  k(2) < j(3),
    D_23_u3 = (g1 ** R_23_u3) * (1 / PRF_23_u3)
    #D_23_u2 sent to user



    #with auth3, k=3
    #auth2, j=2
    g = y_2 ** x_3
    h = g1
    R_32_u3 = group.random(ZR)
    #since k(3) > j(2) ? is true
    gamma_3 = delta_32 = 1
    alpha_3 = delta_32 * R_32_u3
    beta_3 = s_23
    #since  k(3) > j(2),
    D_32_u3 = (g1 ** R_32_u3) * PRF_23_u3
    #D_32_u3 sent to user

    #auth3, j=1
    g = y_1 ** x_3
    h = g1
    R_31_u3 = group.random(ZR)
    #since k(3) > j(1) ? is true
    gamma_3 = delta_31 = 1
    alpha_3 = delta_31 * R_31_u3
    beta_3 = s_13
    #since  k(3) > j(1),
    D_31_u3 = (g1 ** R_31_u3) * PRF_13_u3
    #D_31_u3 sent to user




    #POLYNOMIAL CALCULATION setting d_k = 2
    #a1x + a0
    #stored as [a1, a0]
    #auth1
    p_1_0_u1 = v_1 - (R_12_u1 + R_13_u1)
    coeff_auth1_u1 = [group.random(ZR)]
    coeff_auth1_u1.append(p_1_0_u1)

    p_1_0_u2 = v_1 - (R_12_u2 + R_13_u2)
    coeff_auth1_u2 = [group.random(ZR)]
    coeff_auth1_u2.append(p_1_0_u2)

    p_1_0_u3 = v_1 - (R_12_u3 + R_13_u3)
    coeff_auth1_u3 = [group.random(ZR)]
    coeff_auth1_u3.append(p_1_0_u3)


    #auth2
    p_2_0_u1 = v_2 - (R_21_u1 + R_23_u1)
    coeff_auth2_u1 = [group.random(ZR)]
    coeff_auth2_u1.append(p_2_0_u1)

    p_2_0_u2 = v_2 - (R_21_u2 + R_23_u2)
    coeff_auth2_u2 = [group.random(ZR)]
    coeff_auth2_u2.append(p_2_0_u2)

    p_2_0_u3 = v_2 - (R_21_u3 + R_23_u3)
    coeff_auth2_u3 = [group.random(ZR)]
    coeff_auth2_u3.append(p_2_0_u3)

    #auth3
    p_3_0_u1 = v_3 - (R_31_u1 + R_32_u1)
    coeff_auth3_u1 = [group.random(ZR)]
    coeff_auth3_u1.append(p_3_0_u1)

    p_3_0_u2 = v_3 - (R_31_u2 + R_32_u2)
    coeff_auth3_u2 = [group.random(ZR)]
    coeff_auth3_u2.append(p_3_0_u2)

    p_3_0_u3 = v_3 - (R_31_u3 + R_32_u3)
    coeff_auth3_u3 = [group.random(ZR)]
    coeff_auth3_u3.append(p_3_0_u3)

    #auth setting S_k_i for user 1
    #auth1
    S_1_1_u1 = g1 ** (p(1, coeff_auth1_u1) * (1 / t_1a1))
    S_1_2_u1 = g1 ** (p(2, coeff_auth1_u1) * (1 / t_1a2))
    S_1_3_u1 = g1 ** (p(3, coeff_auth1_u1) * (1 / t_1a3))
    S_1_4_u1 = g1 ** (p(4, coeff_auth1_u1) * (1 / t_1a4))

    #auth2
    S_2_1_u1 = g1 ** (p(1, coeff_auth2_u1) * (1 / t_2a1))
    S_2_2_u1 = g1 ** (p(2, coeff_auth2_u1) * (1 / t_2a2))
    S_2_3_u1 = g1 ** (p(3, coeff_auth2_u1) * (1 / t_2a3))
    S_2_4_u1 = g1 ** (p(4, coeff_auth2_u1) * (1 / t_2a4))

    #auth3
    S_3_1_u1 = g1 ** (p(1, coeff_auth3_u1) * (1 / t_3a1))
    S_3_2_u1 = g1 ** (p(2, coeff_auth3_u1) * (1 / t_3a2))
    S_3_3_u1 = g1 ** (p(3, coeff_auth3_u1) * (1 / t_3a3))
    S_3_4_u1 = g1 ** (p(4, coeff_auth3_u1) * (1 / t_3a4))

    #auth setting S_k_i for user 2
    #auth1
    S_1_1_u2 = g1 ** (p(1, coeff_auth1_u2) * (1 / t_1a1))
    S_1_2_u2 = g1 ** (p(2, coeff_auth1_u2) * (1 / t_1a2))
    S_1_3_u2 = g1 ** (p(3, coeff_auth1_u2) * (1 / t_1a3))
    S_1_4_u2 = g1 ** (p(4, coeff_auth1_u2) * (1 / t_1a4))

    #auth2
    S_2_1_u2 = g1 ** (p(1, coeff_auth2_u2) * (1 / t_2a1))
    S_2_2_u2 = g1 ** (p(2, coeff_auth2_u2) * (1 / t_2a2))
    S_2_3_u2 = g1 ** (p(3, coeff_auth2_u2) * (1 / t_2a3))
    S_2_4_u2 = g1 ** (p(4, coeff_auth2_u2) * (1 / t_2a4))

    #auth3
    S_3_1_u2 = g1 ** (p(1, coeff_auth3_u2) * (1 / t_3a1))
    S_3_2_u2 = g1 ** (p(2, coeff_auth3_u2) * (1 / t_3a2))
    S_3_3_u2 = g1 ** (p(3, coeff_auth3_u2) * (1 / t_3a3))
    S_3_4_u2 = g1 ** (p(4, coeff_auth3_u2) * (1 / t_3a4))

    #auth setting S_k_i for user 3
    #auth1
    S_1_1_u3 = g1 ** (p(1, coeff_auth1_u3) * (1 / t_1a1))
    S_1_2_u3 = g1 ** (p(2, coeff_auth1_u3) * (1 / t_1a2))
    S_1_3_u3 = g1 ** (p(3, coeff_auth1_u3) * (1 / t_1a3))
    S_1_4_u3 = g1 ** (p(4, coeff_auth1_u3) * (1 / t_1a4))

    #auth2
    S_2_1_u3 = g1 ** (p(1, coeff_auth2_u3) * (1 / t_2a1))
    S_2_2_u3 = g1 ** (p(2, coeff_auth2_u3) * (1 / t_2a2))
    S_2_3_u3 = g1 ** (p(3, coeff_auth2_u3) * (1 / t_2a3))
    S_2_4_u3 = g1 ** (p(4, coeff_auth2_u3) * (1 / t_2a4))

    #auth3
    S_3_1_u3 = g1 ** (p(1, coeff_auth3_u3) * (1 / t_3a1))
    S_3_2_u3 = g1 ** (p(2, coeff_auth3_u3) * (1 / t_3a2))
    S_3_3_u3 = g1 ** (p(3, coeff_auth3_u3) * (1 / t_3a3))
    S_3_4_u3 = g1 ** (p(4, coeff_auth3_u3) * (1 / t_3a4))

    #user u1 calculates D_u
    D_u1 = D_12_u1 * D_13_u1 * D_21_u1 * D_23_u1 * D_31_u1 * D_32_u1

    if D_u1 == (g1 ** (R_12_u1 + R_13_u1 + R_21_u1 + R_23_u1 + R_31_u1 + R_32_u1)):
        pass
        #        print("D_u1 check succeeded")
    else:
        pass
#        print("D_u1 check failed")

    #user u2 calculates D_u
    D_u2 = D_12_u2 * D_13_u2 * D_21_u2 * D_23_u2 * D_31_u2 * D_32_u2
    if D_u2 == (g1 ** (R_12_u2 + R_13_u2 + R_21_u2 + R_23_u2 + R_31_u2 + R_32_u2)):
        pass
#        print("D_u2 check succeeded")
    else:
        pass
#        print("D_u2 check failed")

    #user u3 calculates D_u
    D_u3 = D_12_u3 * D_13_u3 * D_21_u3 * D_23_u3 * D_31_u3 * D_32_u3
    if D_u3 == (g1 ** (R_12_u3 + R_13_u3 + R_21_u3 + R_23_u3 + R_31_u3 + R_32_u3)):
        pass
#        print("D_u3 check succeeded")
    else:
        pass
#        print("D_u3 check failed")

    #Compose a dictionary for easy serailization (bytecode dictionary)
    keys = ('Y', 'g2', 'T_1a1', 'T_1a2', 'T_2a2', 'T_2a3', 'T_3a1', 'T_3a3', 'q', 'S_1_1_u1', 'g1', 'coeff_auth1_u1', 'S_1_2_u1', 'S_2_2_u1', 'coeff_auth2_u1', 'S_2_3_u1', 'S_3_1_u1', 'coeff_auth3_u1', 'S_3_3_u1', 'D_u1', 'group')
    vals = (Y, g2, T_1a1, T_1a2, T_2a2, T_2a3, T_3a1, T_3a3, q, S_1_1_u1, g1, coeff_auth1_u1, S_1_2_u1, S_2_2_u1, coeff_auth2_u1, S_2_3_u1, S_3_1_u1, coeff_auth3_u1, S_3_3_u1, D_u1, 'SS512')
    ser_vals = []
    for val in vals:
        ser_vals.append(objectToBytes(val, group).decode("utf8"))
    setup_dict = dict(zip(keys,tuple(ser_vals)))
    setup_json = json.JSONEncoder().encode(setup_dict)


    return setup_json

########ENCRYPTION############
# msg, Y, g2, T_1a1, T_1a2, T_2a2, T_2a3, T_3a1, T_3a3
def encrypt(Y, g2, T_1a1, T_1a2, T_2a2, T_2a3, T_3a1, T_3a3, group):
    #msg encrypted with a1,a2 attr from auth1 and a2,a3 attr from auth2 and a1,a3 attr from auth3
    msg = group.random(GT)
#    print("MSG")
#    print(msg)    
    s = group.random(ZR)

    E_0 = (msg * (Y ** s))

    E_1 = (g2 ** s)

    #C_k_i for all k auths in system
    C_1_1 = (T_1a1 ** s)

    C_1_2 = (T_1a2 ** s)

    C_2_2 = (T_2a2 ** s)

    C_2_3 = (T_2a3 ** s)

    C_3_1 = (T_3a1 ** s)

    C_3_3 = (T_3a3 ** s)


    enc_msg = (E_0, E_1, (C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3))
#    print("ENC_MSG")
#    print(enc_msg)

    #Compose a dictionary for easy serialization
    keys = ('E_0', 'E_1', 'C_1_1', 'C_1_2', 'C_2_2', 'C_2_3', 'C_3_1', 'C_3_3', 'msg', 's')
    vals = (E_0, E_1, C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3, msg, s)
    ser_vals = []
    for val in vals:
        ser_vals.append(objectToBytes(val, group).decode("utf8"))
    encrypt_dict = dict(zip(keys,tuple(ser_vals)))


    return E_0, E_1, C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3, msg, s, encrypt_dict



########ENCRYPTION############
# msg, Y, g2, T_1a1, T_1a2, T_2a2, T_2a3, T_3a1, T_3a3
def encrypt2(setup_json):
    setup_dict = parseInDict(setup_json)

    group = PairingGroup('SS512')
    #msg encrypted with a1,a2 attr from auth1 and a2,a3 attr from auth2 and a1,a3 attr from auth3
    msg = group.random(GT)
#    print("MSG")
#    print(msg)    
    s = group.random(ZR)

    Y = setup_dict['Y']
    g2 = setup_dict['g2']
    T_1a1 = setup_dict['T_1a1']
    T_1a2 = setup_dict['T_1a2']
    T_2a2 = setup_dict['T_2a2']
    T_2a3 = setup_dict['T_2a3']
    T_3a1 = setup_dict['T_3a1']
    T_3a3 = setup_dict['T_3a3']

    E_0 = (msg * (Y ** s))

    E_1 = (g2 ** s)

    #C_k_i for all k auths in system
    C_1_1 = (T_1a1 ** s)

    C_1_2 = (T_1a2 ** s)

    C_2_2 = (T_2a2 ** s)

    C_2_3 = (T_2a3 ** s)

    C_3_1 = (T_3a1 ** s)

    C_3_3 = (T_3a3 ** s)


    enc_msg = (E_0, E_1, (C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3))
#    print("ENC_MSG")
#    print(enc_msg)

    #Compose a dictionary for easy serialization
    keys = ('E_0', 'E_1', 'C_1_1', 'C_1_2', 'C_2_2', 'C_2_3', 'C_3_1', 'C_3_3', 'msg', 's')
    vals = (E_0, E_1, C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3, msg, s)
    ser_vals = []
    for val in vals:
        ser_vals.append(objectToBytes(val, group).decode("utf8"))
    encrypt_dict = dict(zip(keys,tuple(ser_vals)))

    enc_json = json.JSONEncoder().encode(encrypt_dict)
    return enc_json

def stringifyDict(in_dict):
    group = PairingGroup('SS512')
    for (key, value) in in_dict.items():
        in_dict[key] = objectToBytes(val, group).decode("utf8") 

    return json.JSONEncoder().encode(in_dict)

def dictifyString(in_string):
    group = PairingGroup('SS512')
    out_dict = json.JSONDecoder().decode(in_string)
    for (key, val) in out_dict.items():
        val_bytes = val.encode("utf8")
        out_dict[key] = bytesToObject(val_bytes, group)



###########################
#Interpolation:
def interpolation(q):
    L1_0_Auth1 = 2
    L2_0_Auth1 = -1
    L2_0_Auth2 = 3
    L3_0_Auth2 = -2
    L1_0_Auth3 = (3 * modinv(2,q)) % q
    L3_0_Auth3 = - ((1 * modinv(2,q)) % q)
    return L1_0_Auth1, L2_0_Auth1, L2_0_Auth2, L3_0_Auth2, L1_0_Auth3, L3_0_Auth3

########DECRYPTION###########
def decrypt(msg, S_1_1_u1, C_1_1, g1, g2, coeff_auth1_u1, S_1_2_u1, C_1_2, S_2_2_u1, C_2_2, coeff_auth2_u1, S_2_3_u1, C_2_3, S_3_1_u1, C_3_1, coeff_auth3_u1, S_3_3_u1, C_3_3, D_u1, E_1, E_0, q, s):
    ##User 1 decrypting the msg
    #for each auth 1, 2, 3

    #a1,a2 attr from auth1
    #a1
    auth1_pair_a1 = pair(S_1_1_u1, C_1_1)
    if auth1_pair_a1 == (pair(g1,g2) ** (s * p(1, coeff_auth1_u1))):
        pass
#        print("auth1 attr1 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr1 dec 1 (a) step failed")
    auth1_pair_a2 = pair(S_1_2_u1, C_1_2)
    if auth1_pair_a2 == (pair(g1,g2) ** (s * p(2, coeff_auth1_u1))):
        pass
#        print("auth1 attr2 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr2 dec 1 (a) step failed")
    #interpolate values for P_1
    P_1 = (auth1_pair_a1 ** 2) * (auth1_pair_a2 ** (-1))
    if P_1 == (pair(g1,g2) ** (s * p(0, coeff_auth1_u1))):
        pass
#        print("auth1 dec 1(b) Successful")
    else:
        pass
#        print("auth1 dec 1(b) failed")



    #a2,a3 attr from auth2
    auth2_pair_a2 = pair(S_2_2_u1, C_2_2)
    if auth2_pair_a2 == (pair(g1,g2) ** (s * p(2, coeff_auth2_u1))):
        pass
#        print("auth2 attr2 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr2 dec 1 (a) step failed")
    auth2_pair_a3 = pair(S_2_3_u1, C_2_3)
    if auth2_pair_a3 == (pair(g1,g2) ** (s * p(3, coeff_auth2_u1))):
        pass
#        print("auth2 attr3 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr3 dec 1 (a) step failed")
    #interpolate values for P_2
    P_2 = (auth2_pair_a2 ** 3) * ((auth2_pair_a3 ** (-1)) ** 2)
    if P_2 == (pair(g1,g2) ** (s * p(0, coeff_auth2_u1))):
        pass
#        print("auth2 dec 1(b) Successful")
    else:
        pass
#        print("auth2 dec 1(b) failed")



    #a1,a3 attr from auth3
    auth3_pair_a1 = pair(S_3_1_u1, C_3_1)
    if auth3_pair_a1 == (pair(g1,g2) ** (s * p(1, coeff_auth3_u1))):
        pass
#        print("auth3 attr1 dec 1 (a) step Successful")
    else:
        pass
#        print("auth3 attr1 dec 1 (a) step failed")
    auth3_pair_a3 = pair(S_3_3_u1, C_3_3)
    if auth3_pair_a3 == (pair(g1,g2) ** (s * p(3, coeff_auth3_u1))):
        pass
#        print("auth3 attr3 dec 1 (a) step Successful")
    else:
        pass
#        print("auth3 attr3 dec 1 (a) step failed")
    #interpolate values for P_3
    # P_3 =  (auth3_pair_a1 ** L1_0_Auth3) * (auth3_pair_a3 ** L3_0_Auth3)    
    P_3 =  ((auth3_pair_a1 ** 3) ** modinv(2,q)) * ((auth3_pair_a3 ** -1) ** modinv(2,q))
    if P_3 == (pair(g1,g2) ** (s * p(0, coeff_auth3_u1))):
        pass
#        print("auth3 dec 1(b) Successful")
    else:
        pass
#        print("auth3 dec 1(b) failed")




    Q = P_1 * P_2 * P_3


    dec_step3 = ((pair(D_u1, E_1)) * Q)

    decrypted_msg = E_0 * (1 / dec_step3)


    if msg == decrypted_msg:
        pass
#        print("Message Decryption Successful")
    else:
        pass
#        print("Message Decryption Failed")


########DECRYPTION###########
def decrypt2(setup_json, enc_json):
    setup_dict = parseInDict(setup_json)
    encrypt_dict = parseInDict(enc_json)
    msg = encrypt_dict['msg']
    S_1_1_u1 = setup_dict['S_1_1_u1']
    C_1_1 = encrypt_dict['C_1_1']
    g1 = setup_dict['g1']
    g2 = setup_dict['g2']
    coeff_auth1_u1 = setup_dict['coeff_auth1_u1']
    S_1_2_u1 = setup_dict['S_1_2_u1']
    C_1_2 = encrypt_dict['C_1_2']
    S_2_2_u1 = setup_dict['S_2_2_u1']
    C_2_2 = encrypt_dict['C_2_2']
    coeff_auth2_u1 = setup_dict['coeff_auth2_u1']
    S_2_3_u1 = setup_dict['S_2_3_u1']
    C_2_3 = encrypt_dict['C_2_3']
    S_3_1_u1 = setup_dict['S_3_1_u1']
    C_3_1 = encrypt_dict['C_3_1']
    coeff_auth3_u1 = setup_dict['coeff_auth3_u1']
    S_3_3_u1 = setup_dict['S_3_3_u1']
    C_3_3 = encrypt_dict['C_3_3']
    D_u1 = setup_dict['D_u1']
    E_1 = encrypt_dict['E_1']
    E_0 = encrypt_dict['E_0']
    q = setup_dict['q']
    s = encrypt_dict['s']
    group = PairingGroup('SS512')

    ##User 1 decrypting the msg
    #for each auth 1, 2, 3

    #a1,a2 attr from auth1
    #a1
    auth1_pair_a1 = pair(S_1_1_u1, C_1_1)
    if auth1_pair_a1 == (pair(g1,g2) ** (s * p(1, coeff_auth1_u1))):
        pass
#        print("auth1 attr1 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr1 dec 1 (a) step failed")
    auth1_pair_a2 = pair(S_1_2_u1, C_1_2)
    if auth1_pair_a2 == (pair(g1,g2) ** (s * p(2, coeff_auth1_u1))):
        pass
#        print("auth1 attr2 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr2 dec 1 (a) step failed")
    #interpolate values for P_1
    P_1 = (auth1_pair_a1 ** 2) * (auth1_pair_a2 ** (-1))
    if P_1 == (pair(g1,g2) ** (s * p(0, coeff_auth1_u1))):
        pass
#        print("auth1 dec 1(b) Successful")
    else:
        pass
#        print("auth1 dec 1(b) failed")



    #a2,a3 attr from auth2
    auth2_pair_a2 = pair(S_2_2_u1, C_2_2)
    if auth2_pair_a2 == (pair(g1,g2) ** (s * p(2, coeff_auth2_u1))):
        pass
#        print("auth2 attr2 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr2 dec 1 (a) step failed")
    auth2_pair_a3 = pair(S_2_3_u1, C_2_3)
    if auth2_pair_a3 == (pair(g1,g2) ** (s * p(3, coeff_auth2_u1))):
        pass
#        print("auth2 attr3 dec 1 (a) step Successful")
    else:
        pass
#        print("auth1 attr3 dec 1 (a) step failed")
    #interpolate values for P_2
    P_2 = (auth2_pair_a2 ** 3) * ((auth2_pair_a3 ** (-1)) ** 2)
    if P_2 == (pair(g1,g2) ** (s * p(0, coeff_auth2_u1))):
        pass
#        print("auth2 dec 1(b) Successful")
    else:
        pass
#        print("auth2 dec 1(b) failed")



    #a1,a3 attr from auth3
    auth3_pair_a1 = pair(S_3_1_u1, C_3_1)
    if auth3_pair_a1 == (pair(g1,g2) ** (s * p(1, coeff_auth3_u1))):
        pass
#        print("auth3 attr1 dec 1 (a) step Successful")
    else:
        pass
#        print("auth3 attr1 dec 1 (a) step failed")
    auth3_pair_a3 = pair(S_3_3_u1, C_3_3)
    if auth3_pair_a3 == (pair(g1,g2) ** (s * p(3, coeff_auth3_u1))):
        pass
#        print("auth3 attr3 dec 1 (a) step Successful")
    else:
        pass
#        print("auth3 attr3 dec 1 (a) step failed")
    #interpolate values for P_3
    # P_3 =  (auth3_pair_a1 ** L1_0_Auth3) * (auth3_pair_a3 ** L3_0_Auth3)    
    P_3 =  ((auth3_pair_a1 ** 3) ** modinv(2,q)) * ((auth3_pair_a3 ** -1) ** modinv(2,q))
    if P_3 == (pair(g1,g2) ** (s * p(0, coeff_auth3_u1))):
        pass
#        print("auth3 dec 1(b) Successful")
    else:
        pass
#        print("auth3 dec 1(b) failed")




    Q = P_1 * P_2 * P_3


    dec_step3 = ((pair(D_u1, E_1)) * Q)

    decrypted_msg = E_0 * (1 / dec_step3)


    if msg == decrypted_msg:
        pass
#        print("Message Decryption Successful")
    else:
        pass
#        print("Message Decryption Failed")

    key = objectToBytes(decrypted_msg, group).decode("utf8")    

    return key




def encryptPayload(symKey):
    ciphertext = ""
    with open("decrypted_text.txt", "r") as f:
        msg = f.read()
        key = sha256(symKey.encode('utf8')).digest()
        cipher = AuthenticatedCryptoAbstraction(key)
        ciphertext = cipher.encrypt(msg)

    with open("encrypted_text.txt", "w") as f2:
        f2.write(json.dumps(ciphertext))

    return

def encryptPayload2(symKey, in_string):
#    key = sha256(symKey).digest()
    key = sha256(symKey.encode('utf8')).digest()
    cipher = AuthenticatedCryptoAbstraction(key)
    ciphertext = json.dumps(cipher.encrypt(in_string))
    return ciphertext


def decryptPayload(symKey):
    msg = ""
    with open("encrypted_text.txt", "r") as f:
        ciphertext = json.loads(f.read())
        key = sha256(symKey.encode('utf8')).digest()
        cipher = AuthenticatedCryptoAbstraction(key)
        msg = cipher.decrypt(ciphertext).decode('utf8')

    with open("decrypted_text.txt", "w") as f2:
        f2.write(msg)

    return

def decryptPayload2(symKey, in_str):
    ciphertext = json.loads(in_str)
    key = sha256(symKey.encode('utf8')).digest()
    cipher = AuthenticatedCryptoAbstraction(key)
    msg = cipher.decrypt(ciphertext)
    return msg

def saveSetupValues():
    Y, g2, T_1a1, T_1a2, T_2a2, T_2a3, T_3a1, T_3a3, q, S_1_1_u1, g1, coeff_auth1_u1, S_1_2_u1, S_2_2_u1, coeff_auth2_u1, S_2_3_u1, S_3_1_u1, coeff_auth3_u1, S_3_3_u1, D_u1, group, setup_dict = setup()
#    print(setup_dict)
    setup_json = json.JSONEncoder().encode(setup_dict)
    with open("globalvars.cfg", "w") as f:
        json.dump(setup_json, f)

def saveEncryptValues(encrypt_dict):
    encrypt_json = json.JSONEncoder().encode(encrypt_dict)
    with open("encryptvars.cfg", "w") as f:
        json.dump(encrypt_json, f)

def parseInSetupConfig():
    group = PairingGroup('SS512')
    with open("globalvars.cfg", "r") as f:
        setup_json = json.load(f)
        setup_dict = json.JSONDecoder().decode(setup_json)

#    print(type(setup_dict))
    for (key, val) in setup_dict.items():
        val_bytes = val.encode("utf8")
        setup_dict[key] = bytesToObject(val_bytes, group)

    return setup_dict

def parseInDict(json_str):
    group = PairingGroup('SS512')
    mdict = json.JSONDecoder().decode(json_str)
    for (key, val) in mdict.items():
        val_bytes = val.encode("utf8")
        mdict[key] = bytesToObject(val_bytes, group)
    return mdict

def parseInEncryptConfig():
    group = PairingGroup('SS512')
    with open("encryptvars.cfg", "r") as f:
        encrypt_json = json.load(f)
        encrypt_dict = json.JSONDecoder().decode(encrypt_json)

    for (key, val) in encrypt_dict.items():
        val_bytes = val.encode("utf8")
        encrypt_dict[key] = bytesToObject(val_bytes, group)

    return encrypt_dict

#if sys.argv[1] == "s":
##    print("Attempting setup...")
##    print("Attempting to save global variables to a sharable file.")
#    saveSetupValues()
##    print("attempting to reload the variables")
#    setup_dict = parseInSetupConfig()
##    print(type(setup_dict))
##    print(setup_dict.keys())
##    print("#########################")
##    print(setup_dict['Y'])
#
#if sys.argv[1] == "e":
##    print("Attempting to encrypt.")
##    print("Starting Setup...")
#    setup_dict = parseInSetupConfig()
##    print("Setup successful!")
##    print("Encrypting Symmetric key.")
#    encrypt_dict = encrypt2(setup_dict)
#    saveEncryptValues(encrypt_dict)
#    encryptPayload(encrypt_dict['msg'])
##    print("Encryption Successful!")
##    print("Saving necessary values to a file.")
#    # msg, S_1_1_u1, C_1_1, g1, g2, coeff_auth1_u1, S_1_2_u1, C_1_2, L1_0_Auth1, L2_0_Auth1, S_2_2_u1, C_2_2, coeff_auth2_u1, S_2_3_u1, C_2_3, S_3_1_u1, C_3_1, coeff_auth3_u1, S_3_3_u1, C_3_3, D_u1, E_1, E_0, q, s
#
#if sys.argv[1] == "d":
##    print("Attempting to read in setup variables.")
#    setup_dict = parseInSetupConfig()
##    print("Successfully completed setup!")
##    print("Attempting to read in encrypted variables.")
#    encrypt_dict = parseInEncryptConfig()
##    print("Successfully found encrypted vars.")
##    print("Attempting to decrypt message...")
#    symKey = decrypt2(setup_dict, encrypt_dict)
##    print("Attempting to decrypt encrypted_text.txt")
#    decryptPayload(symKey)
##    print("Thank you!")
#
#
#if sys.argv[1] == "demo":
#    Y, g2, T_1a1, T_1a2, T_2a2, T_2a3, T_3a1, T_3a3, q, S_1_1_u1, g1, coeff_auth1_u1, S_1_2_u1, S_2_2_u1, coeff_auth2_u1, S_2_3_u1, S_3_1_u1, coeff_auth3_u1, S_3_3_u1, D_u1, group, setup_dict = setup()
#    E_0, E_1, C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3, msg, s, encrypt_dict = encrypt(Y, g2, T_1a1, T_1a2, T_2a2, T_2a3, T_3a1, T_3a3, group)
#    L1_0_Auth1, L2_0_Auth1, L2_0_Auth2, L3_0_Auth2, L1_0_Auth3, L3_0_Auth3 = interpolation(q)
#    decrypt(msg, S_1_1_u1, C_1_1, g1, g2, coeff_auth1_u1, S_1_2_u1, C_1_2, S_2_2_u1, C_2_2, coeff_auth2_u1, S_2_3_u1, C_2_3, S_3_1_u1, C_3_1, coeff_auth3_u1, S_3_3_u1, C_3_3, D_u1, E_1, E_0, q, s)
#
#if sys.argv[1] == "test":
#    saveSetupValues()
#    setup_dict = parseInSetupConfig()
#    encrypt_dict = encrypt2(setup_dict)
#    saveEncryptValues(encrypt_dict)
#    encrypt_dict = parseInEncryptConfig()
#    decrypt2(setup_dict, encrypt_dict)
