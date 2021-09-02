#ifdef __cplusplus
extern "C"
{
#endif

#ifndef SERIAL_MULTABE_H
#define SERIAL_MULTABE_H

struct SetupVars {
    unsigned char *Y, *g2, *T_1a1, *T_1a2, *T_2a2, *T_2a3, *T_3a1, *T_3a3, *S_1_1_u1, *g1, *coeff_auth1_u1_0, *coeff_auth1_u1_1, *S_1_2_u1, *S_2_2_u1, *coeff_auth2_u1_0, *coeff_auth2_u1_1, *S_2_3_u1, *coeff_auth3_u1_0, *coeff_auth3_u1_1, *S_3_1_u1, *S_3_3_u1, *D_u1, *temp_1_GT, *temp_1_Zr, *temp_2_Zr, *e_g1g2;

};

struct EncryptVars {
    unsigned char *E_0, *E_1, *C_1_1, *C_1_2, *C_2_2, *C_2_3, *C_3_1, *C_3_3, *msg, *s, *L1_0_Auth1, *L2_0_Auth1, *L2_0_Auth2, *L3_0_Auth2, *L1_0_Auth3, *L3_0_Auth3;
};

struct SetupVars* c_setup();
struct EncryptVars* c_encrypt(struct SetupVars* setupvars);
int c_decrypt(struct SetupVars* setupvars,struct EncryptVars* encryptvars);
void c_test(unsigned char* data);
#endif
#ifdef __cplusplus
}
#endif
