//#define PBC_DEBUG
#include <stdint.h> // for intptr_t
#include "pbc.h"
#include "pbc_utils.h"  // for UNUSED_VAR
#include <time.h>
#include "serial_multabe_2.h"
//Compile with: gcc multabe.c -o multabe -lpbc -lgmp -I /usr/local/include/pbc
//Run with: ./multabe 9563


pbc_param_t param;

int generate(pbc_cm_t cm, void *data) {
    UNUSED_VAR(data);
//    pbc_info("gendparam: computing Hilbert polynomial and finding roots...");
    pbc_param_init_d_gen(param, cm);
//    pbc_param_init_a_gen(param, 160, 512);
//    pbc_info("gendparam: bits in q = %zu\n", mpz_sizeinbase(cm->q, 2));
    //pbc_param_out_str(stdout, param);
    //pbc_param_clear(param);
    return 1;
}
struct elementstruc
{
    unsigned char *Y;
};
/*
struct SetupVars {
	unsigned char *Y, *g2, *T_1a1, *T_1a2, *T_2a2, *T_2a3, *T_3a1, *T_3a3, *S_1_1_u1, *g1, *coeff_auth1_u1_0, *coeff_auth1_u1_1, *S_1_2_u1, *S_2_2_u1, *coeff_auth2_u1_0, *coeff_auth2_u1_1, *S_2_3_u1, *coeff_auth3_u1_0, *coeff_auth3_u1_1, *S_3_1_u1, *S_3_3_u1, *D_u1, *temp_1_GT, *temp_1_Zr, *temp_2_Zr, *e_g1g2;

};

struct EncryptVars {
	unsigned char *E_0, *E_1, *C_1_1, *C_1_2, *C_2_2, *C_2_3, *C_3_1, *C_3_3, *msg, *s, *L1_0_Auth1, *L2_0_Auth1, *L2_0_Auth2, *L3_0_Auth2, *L1_0_Auth3, *L3_0_Auth3;
};
*/

void c_test(unsigned char* data) {
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, fopen("./a.param","r"));
    if (!count) pbc_die("input error");
    int res = pairing_init_set_buf(pairing,param, count);
//    if (res == 0) //printf("success\n");



    element_t randomelement;
    element_init_GT(randomelement, pairing);
    element_from_bytes(randomelement, data);

//    element_printf("Read Y: %B\n\n",randomelement);

    return;
 }

struct SetupVars* c_setup() {
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, fopen("./a.param","r"));
    if (!count) pbc_die("input error");
    int res = pairing_init_set_buf(pairing,param, count);
//    if (res == 0) //printf("success\n");

    element_t D_u1, test_D_u1, Q, dec_step3, decrypted_msg, auth1_pair_a1, auth1_pair_a2, P_1, temp_auth1_pair_a1, temp_auth1_pair_a2, temp_P_1, temp_auth2_pair_a3, P_2, temp_P_2, auth2_pair_a3, auth2_pair_a2, temp_auth2_pair_a2, temp_P_3, P_3, temp_auth3_pair_a3, auth3_pair_a3, temp_auth3_pair_a1, auth3_pair_a1, msg, s, E_0, E_1, C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3, L1_0_Auth1, L2_0_Auth1, L2_0_Auth2, L3_0_Auth2, L1_0_Auth3, L3_0_Auth3, S_1_1_u1, S_1_2_u1, S_1_3_u1, S_1_4_u1, S_2_1_u1, S_2_2_u1, S_2_3_u1, S_2_4_u1, S_3_1_u1, S_3_2_u1, S_3_3_u1, S_3_4_u1, S_1_1_u2, S_1_2_u2, S_1_3_u2, S_1_4_u2, S_2_1_u2, S_2_2_u2, S_2_3_u2, S_2_4_u2, S_3_1_u2, S_3_2_u2, S_3_3_u2, S_3_4_u2, S_1_1_u3, S_1_2_u3, S_1_3_u3, S_1_4_u3, S_2_1_u3, S_2_2_u3, S_2_3_u3, S_2_4_u3, S_3_1_u3, S_3_2_u3, S_3_3_u3, S_3_4_u3, coeff_auth1_u1_0, coeff_auth1_u1_1, p_1_0_u1, p_1_0_u2, coeff_auth1_u2[2], p_1_0_u3, coeff_auth1_u3[2], p_2_0_u1, coeff_auth2_u1_0, coeff_auth2_u1_1, p_2_0_u2, coeff_auth2_u2[2], p_2_0_u3, coeff_auth2_u3[2], p_3_0_u1, coeff_auth3_u1_0, coeff_auth3_u1_1, p_3_0_u2, coeff_auth3_u2[2], p_3_0_u3, coeff_auth3_u3[2], g1, g2, x, y, r, gt, r1, u1, u2, u3, e_g1g2, s_12, s_23, s_13, v_1, Y_1, x_1, y_1, t_1a1, T_1a1, t_1a2, T_1a2, t_1a3, T_1a3, t_1a4, T_1a4, v_2, Y_2, x_2, y_2, t_2a1, T_2a1, t_2a2, T_2a2, t_2a3, T_2a3, t_2a4, T_2a4, v_3, Y_3, x_3, y_3, t_3a1, T_3a1, t_3a2, T_3a2, t_3a3, T_3a3, t_3a4, T_3a4, PRF_12_u1, PRF_12_u2, PRF_12_u3, PRF_23_u1, PRF_23_u2, PRF_23_u3, PRF_13_u1, PRF_13_u2, PRF_13_u3, Y, t1, t2, t3, h, R_12_u1, gamma_1, delta_12, alpha_1, beta_1, D_12_u1, R_13_u1, delta_13, D_13_u1, R_21_u1, gamma_2, delta_21, alpha_2, beta_2, D_21_u1, R_23_u1, delta_23, D_23_u1, R_32_u1, gamma_3, alpha_3, beta_3, delta_32, D_32_u1, R_31_u1, D_31_u1, R_12_u2, D_12_u2, R_13_u2, D_13_u2, R_21_u2, D_21_u2, R_23_u2, D_23_u2, R_32_u2, D_32_u2, R_31_u2, D_31_u2, R_12_u3, D_12_u3, R_13_u3, D_13_u3, R_21_u3, D_21_u3, R_23_u3, D_23_u3, R_32_u3, D_32_u3, R_31_u3, D_31_u3, delta_31, temp_1_Zr, temp_2_Zr, temp_3_Zr, temp_4_Zr, temp_5_Zr, temp_1_G1, temp_2_G1, temp_3_G1, temp_4_G1, temp_5_G1, temp_1_G2, temp_2_G2, temp_3_G2, temp_4_G2, temp_5_G2, temp_1_GT, temp_2_GT, temp_3_GT, temp_4_GT, temp_5_GT, temp_1, temp_2, temp_3, temp_4, temp_5;

        
    element_init_Zr(temp_1_Zr, pairing); 
    element_init_Zr(temp_2_Zr, pairing); 
    element_init_Zr(temp_3_Zr, pairing); 
    element_init_Zr(temp_4_Zr, pairing); 
    element_init_Zr(temp_5_Zr, pairing); 

    element_init_G1(temp_1_G1, pairing); 
    element_init_G1(temp_2_G1, pairing); 
    element_init_G1(temp_3_G1, pairing); 
    element_init_G1(temp_4_G1, pairing); 
    element_init_G1(temp_5_G1, pairing); 

    element_init_G2(temp_1_G2, pairing); 
    element_init_G2(temp_2_G2, pairing); 
    element_init_G2(temp_3_G2, pairing); 
    element_init_G2(temp_4_G2, pairing); 
    element_init_G2(temp_5_G2, pairing); 

    element_init_GT(temp_1_GT, pairing); 
    element_init_GT(temp_2_GT, pairing); 
    element_init_GT(temp_3_GT, pairing); 
    element_init_GT(temp_4_GT, pairing); 
    element_init_GT(temp_5_GT, pairing); 

    //Setup
    //Setting EC
    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_GT(e_g1g2, pairing);

    //g1 = group.random(G1)
    element_random(g1);
    //g2 = group.random(G2)
    element_random(g2); 
 
    //e_g1g2 = pair(g1, g2)
    element_pairing(e_g1g2, g1,g2); 
/*
    int num_bytes = element_length_in_bytes(g2);

    //printf("bytes: %d\n", num_bytes);

    struct elementstruc *keys = (struct elementstruc*) malloc(sizeof(struct elementstruc));

    keys->Y = (unsigned char*) malloc(num_bytes * sizeof(unsigned char));

    int ret = element_to_bytes(keys->Y, g2);

    element_//printf("\n\n Original e_g1g2: %B\n\n", g2);

    element_t randomelement;
    element_init_GT(randomelement, pairing);
    element_from_bytes(randomelement, keys->Y);

    element_//printf("Read e_g1g2: %B\n\n",randomelement);
*/
    //user GIDs 
    //u1 = group.random(ZR)
    element_init_Zr(u1,pairing);
    element_random(u1);

    //u2 = group.random(ZR)
    element_init_Zr(u2,pairing);
    element_random(u2);
    
    //u3 = group.random(ZR)
    element_init_Zr(u3,pairing);
    element_random(u3);

    //Attributes 1,2,3,4, represented with ai where i is the index used in polynomials
    //a1,a2,a3,a4

    //Secret between Auth1 and Auth2
    //s_12 = group.random(ZR)
    element_init_Zr(s_12,pairing);
    element_random(s_12);

    //Secret between Auth2 and Auth3
    //s_23 = group.random(ZR)
    element_init_Zr(s_23,pairing);
    element_random(s_23);

    //Secret between Auth1 and Auth3
    //s_13 = group.random(ZR)
    element_init_Zr(s_13,pairing);
    element_random(s_13);


    //MPK/MSK Authority 1
    //v_1 = group.random(ZR)
    element_init_Zr(v_1,pairing);
    element_random(v_1);
 
    //Y_1 = (e_g1g2) ** v_1
    element_init_GT(Y_1,pairing);
    element_pow_zn(Y_1, e_g1g2, v_1);
    
    //x_1 = group.random(ZR)
    element_init_Zr(x_1,pairing);
    element_random(x_1);
   
    //y_1 = g1 ** x_1
    element_init_G1(y_1,pairing);
    element_pow_zn(y_1, g1, x_1);

    //t_1a1 = group.random(ZR)
    element_init_Zr(t_1a1,pairing);
    element_random(t_1a1);

    //T_1a1 = g2 ** t_1a1
    element_init_G2(T_1a1,pairing);
    element_pow_zn(T_1a1, g2, t_1a1);

    //t_1a2 = group.random(ZR)
    element_init_Zr(t_1a2,pairing);
    element_random(t_1a2);

    //T_1a2 = g2 ** t_1a2
    element_init_G2(T_1a2,pairing);
    element_pow_zn(T_1a2, g2, t_1a2);

    //t_1a3 = group.random(ZR)
    element_init_Zr(t_1a3,pairing);
    element_random(t_1a3);

    //T_1a3 = g2 ** t_1a3
    element_init_G2(T_1a3,pairing);
    element_pow_zn(T_1a3, g2, t_1a3);

    //t_1a4 = group.random(ZR) 
    element_init_Zr(t_1a4,pairing);
    element_random(t_1a4);

    //T_1a4 = g2 ** t_1a4
    element_init_G2(T_1a4,pairing);
    element_pow_zn(T_1a4, g2, t_1a4);
    
    //MPK/MSK Authority 2
    //v_2 = group.random(ZR)
    element_init_Zr(v_2,pairing);
    element_random(v_2);
 
    //Y_2 = (e_g1g2) ** v_2
    element_init_GT(Y_2,pairing);
    element_pow_zn(Y_2, e_g1g2, v_2);
    
    //x_2 = group.random(ZR)
    element_init_Zr(x_2,pairing);
    element_random(x_2);
   
    //y_2 = g1 ** x_2
    element_init_G1(y_2,pairing);
    element_pow_zn(y_2, g1, x_2);

    //#Attr computation
    //t_2a1 = group.random(ZR)
    element_init_Zr(t_2a1,pairing);
    element_random(t_2a1);

    //T_2a1 = g2 ** t_2a1
    element_init_G2(T_2a1,pairing);
    element_pow_zn(T_2a1, g2, t_2a1);
    
    //t_2a2 = group.random(ZR)
    element_init_Zr(t_2a2,pairing);
    element_random(t_2a2);

    //T_2a2 = g2 ** t_2a2
    element_init_G2(T_2a2,pairing);
    element_pow_zn(T_2a2, g2, t_2a2);
    
    //t_2a3 = group.random(ZR)
    element_init_Zr(t_2a3,pairing);
    element_random(t_2a3);

    //T_2a3 = g2 ** t_2a3
    element_init_G2(T_2a3,pairing);
    element_pow_zn(T_2a3, g2, t_2a3);

    //t_2a4 = group.random(ZR)
    element_init_Zr(t_2a4,pairing);
    element_random(t_2a4);

    //T_2a4 = g2 ** t_2a4
    element_init_G2(T_2a4,pairing);
    element_pow_zn(T_2a4, g2, t_2a4);


    //MPK/MSK Authority 3
    //v_3 = group.random(ZR)
    element_init_Zr(v_3,pairing);
    element_random(v_3);
 
    //Y_3 = (e_g1g2) ** v_3
    element_init_GT(Y_3,pairing);
    element_pow_zn(Y_3, e_g1g2, v_3);
    
    //x_3 = group.random(ZR) 
    element_init_Zr(x_3,pairing);
    element_random(x_3);
  
    //y_3 = g1 ** x_3 
    element_init_G1(y_3,pairing);
    element_pow_zn(y_3, g1, x_3);

    //Attr computation
    //t_3a1 = group.random(ZR)
    element_init_Zr(t_3a1,pairing);
    element_random(t_3a1);
    
    //T_3a1 = g2 ** t_3a1
    element_init_G2(T_3a1,pairing);
    element_pow_zn(T_3a1, g2, t_3a1);

    //t_3a2 = group.random(ZR)
    element_init_Zr(t_3a2,pairing);
    element_random(t_3a2);

    //T_3a2 = g2 ** t_3a2
    element_init_G2(T_3a2,pairing);
    element_pow_zn(T_3a2, g2, t_3a2);

    //t_3a3 = group.random(ZR)
    element_init_Zr(t_3a3,pairing);
    element_random(t_3a3);

    //T_3a3 = g2 ** t_3a3
    element_init_G2(T_3a3,pairing);
    element_pow_zn(T_3a3, g2, t_3a3);

    //t_3a4 = group.random(ZR)
    element_init_Zr(t_3a4,pairing);
    element_random(t_3a4);

    //T_3a4 = g2 ** t_3a4
    element_init_G2(T_3a4,pairing);
    element_pow_zn(T_3a4, g2, t_3a4);


    //Auth1 and Auth2
    //PRF_12_u1 = y_1 ** (x_2 * (1 / (s_12 + u1)))
    element_add(temp_1_Zr,s_12,u1);
    element_div(temp_2_Zr,x_2,temp_1_Zr);

    element_init_G1(PRF_12_u1,pairing);
    element_pow_zn(PRF_12_u1, y_1, temp_1_Zr);      

    //PRF_12_u2 = y_1 ** (x_2 * (1 / (s_12 + u2)))
    element_add(temp_1_Zr,s_12,u2);
    element_div(temp_2_Zr,x_2,temp_1_Zr);

    element_init_G1(PRF_12_u2,pairing);
    element_pow_zn(PRF_12_u2, y_1, temp_1_Zr);

    //PRF_12_u3 = y_1 ** (x_2 * (1 / (s_12 + u3)))
    element_add(temp_1_Zr,s_12,u3);
    element_div(temp_2_Zr,x_2,temp_1_Zr);

    element_init_G1(PRF_12_u3,pairing);
    element_pow_zn(PRF_12_u3, y_1, temp_1_Zr);

    //Auth2 and Auth3
    //PRF_23_u1 = y_2 ** (x_3 * (1 / (s_23 + u1)))
    element_add(temp_1_Zr,s_23,u1);
    element_div(temp_2_Zr,x_3,temp_1_Zr);

    element_init_G1(PRF_23_u1,pairing);
    element_pow_zn(PRF_23_u1, y_2, temp_1_Zr);

    //PRF_23_u2 = y_2 ** (x_3 * (1 / (s_23 + u2)))
    element_add(temp_1_Zr,s_23,u2);
    element_div(temp_2_Zr,x_3,temp_1_Zr);

    element_init_G1(PRF_23_u2,pairing);
    element_pow_zn(PRF_23_u2, y_2, temp_1_Zr);

    //PRF_23_u3 = y_2 ** (x_3 * (1 / (s_23 + u3)))
    element_add(temp_1_Zr,s_23,u3);
    element_div(temp_2_Zr,x_3,temp_1_Zr);

    element_init_G1(PRF_23_u3,pairing);
    element_pow_zn(PRF_23_u3, y_2, temp_1_Zr);

   

    //Auth1 and Auth3
    //PRF_13_u1 = y_1 ** (x_3 * (1 / (s_13 + u1)))
    element_add(temp_1_Zr,s_13,u1);
    element_div(temp_2_Zr,x_3,temp_1_Zr);

    element_init_G1(PRF_13_u1,pairing);
    element_pow_zn(PRF_13_u1, y_1, temp_1_Zr);


    //PRF_13_u2 = y_1 ** (x_3 * (1 / (s_13 + u2)))
    element_add(temp_1_Zr,s_13,u2);
    element_div(temp_2_Zr,x_3,temp_1_Zr);

    element_init_G1(PRF_13_u2,pairing);
    element_pow_zn(PRF_13_u2, y_1, temp_1_Zr);

    //PRF_13_u3 = y_1 ** (x_3 * (1 / (s_13 + u3)))
    element_add(temp_1_Zr,s_13,u3);
    element_div(temp_2_Zr,x_3,temp_1_Zr);

    element_init_G1(PRF_13_u3,pairing);
    element_pow_zn(PRF_13_u3, y_1, temp_1_Zr);


    //All Authorities compute
    //Y = Y_1 * Y_2 * Y_3
    
    element_init_GT(Y,pairing);
    
    element_mul(temp_1_GT,Y_1,Y_2); 
    element_mul(Y,temp_1_GT,Y_3); 

    //Auth1 stores
    //MSK_1 = (x_1, (s_12, s_13), (t_1a1, t_1a2, t_1a3, t_1a4))

    //Auth2 stores
    //MSK_2 = (x_2, (s_12, s_23), (t_2a1, t_2a2, t_2a3, t_2a4))

    //Auth3 stores
    //MSK_3 = (x_3, (s_13, s_23), (t_3a1, t_3a2, t_3a3, t_3a4))


    //system params published,
    //params = (Y, ((y_1, T_1a1, T_1a2, T_1a3, T_1a4), (y_2, T_2a1, T_2a2, T_2a3, T_2a4), (y_3, T_3a1, T_3a2, T_3a3, T_3a4)))


    //########KEY ISSUING############
    //#USER SIGNUP
    //#u1 signup
    //#with auth1, k=1
    //#auth2, j=2
    //g = y_2 ** x_1                    //not sure if needed    
    //h = g1                            //not sure if needed
    //element_init_G1(h,pairing);       //not sure if needed
    //element_set(h,g1);                //not sure if needed
    //R_12_u1 = group.random(ZR)
    element_init_Zr(R_12_u1,pairing);
    element_random(R_12_u1);
    
    //#since k(1) > j(2) ? is false
    //gamma_1 = delta_12 = -1
    //element_init_Zr(gamma_1,pairing);
    //element_set_si(gamma_1, -1);
    //element_init_Zr(delta_12,pairing);
    //element_set_si(delta_12, -1);
 
    //alpha_1 = delta_12 * R_12_u1                  //not sure if needed
    //element_init_Zr(alpha_1,pairing);             //not sure if needed
    //element_mul(alpha_1,delta_12,R_12_u1);        //not sure if needed
    
    //beta_1 = s_12                                 //not sure if needed
    //element_init_Zr(beta_1,pairing);              //not sure if needed
    //element_set(beta_1,s_12);                     //not sure if needed
    
    //#since  k(1) < j(2),
    //D_12_u1 = (g1 ** R_12_u1) * (1 / PRF_12_u1)
    element_init_G1(D_12_u1,pairing);
    element_pow_zn(temp_1_G1, g1, R_12_u1);
    element_div(D_12_u1,temp_1_G1,PRF_12_u1); 

    //#D_12_u1 sent to user
    

    //#auth3, j=3
    //g = y_3 ** x_1    //not sure if needed
    //h = g1            //not sure if needed

    //R_13_u1 = group.random(ZR)
    element_init_Zr(R_13_u1,pairing);
    element_random(R_13_u1);
    
    //#since k(1) > j(3) ? is false
    //gamma_1 = delta_13 = -1
    //element_init_Zr(gamma_1,pairing);
    //element_set_si(gamma_1, -1);
    //element_init_Zr(delta_13,pairing);
    //element_set_si(delta_13, -1);

    //alpha_1 = delta_13 * R_13_u1
    //element_init_Zr(alpha_1,pairing);
    //element_mul(alpha_1,delta_13,R_13_u1);

    //beta_1 = s_13
    //element_init_Zr(beta_1,pairing);
    //element_set(beta_1,s_13);

    //#since  k(1) < j(3),
    //D_13_u1 = (g1 ** R_13_u1) * (1 / PRF_13_u1)
    element_init_G1(D_13_u1,pairing);
    element_pow_zn(temp_1_G1, g1, R_13_u1);
    element_div(D_13_u1,temp_1_G1,PRF_13_u1); 

    //#D_13_u1 sent to user
    


    //#with auth2, k=2
    //#auth1, j=1
    //g = y_1 ** x_2
    //h = g1
    //R_21_u1 = group.random(ZR)
    element_init_Zr(R_21_u1,pairing);
    element_random(R_21_u1);

    //#since k(2) > j(1) ? is true
    //gamma_2 = delta_21 = 1
    //element_init_Zr(gamma_2,pairing);
    //element_set_si(gamma_2, 1);
    //element_init_Zr(delta_21,pairing);
    //element_set_si(delta_21, 1);

    //alpha_2 = delta_21 * R_21_u1
    //element_init_Zr(alpha_2,pairing);
    //element_mul(alpha_2,delta_21,R_21_u1); 

    //beta_2 = s_12
    //#since  k(2) > j(1),
    //D_21_u1 = (g1 ** R_21_u1) * PRF_12_u1
    element_init_G1(D_21_u1,pairing);
    element_pow_zn(temp_1_G1, g1, R_21_u1);
    element_mul(D_21_u1,temp_1_G1,PRF_12_u1); 
    

    //#D_21_u1 sent to user
    //
    //#auth3, j=3
    //g = y_3 ** x_2
    //h = g1
    //R_23_u1 = group.random(ZR)
    element_init_Zr(R_23_u1,pairing);
    element_random(R_23_u1);

    //#since k(2) > j(3) ? is false
    //gamma_2 = delta_23 = -1
    //alpha_2 = delta_23 * R_23_u1
    //beta_2 = s_23
    //element_init_Zr(gamma_2,pairing);
    //element_set_si(gamma_2, -1);
    //element_init_Zr(delta_23,pairing);
    //element_set_si(delta_23, -1);

    //#since  k(2) < j(3),
    //D_23_u1 = (g1 ** R_23_u1) * (1 / PRF_23_u1)
    element_init_G1(D_23_u1,pairing);
    element_pow_zn(temp_1_G1, g1, R_23_u1);
    element_div(D_23_u1,temp_1_G1,PRF_23_u1); 

    //#D_23_u1 sent to user
    

    //#with auth3, k=3
    //#auth2, j=2
    //g = y_2 ** x_3
    //h = g1
    //R_32_u1 = group.random(ZR)
    element_init_Zr(R_32_u1,pairing);
    element_random(R_32_u1);

    //#since k(3) > j(2) ? is true
    //gamma_3 = delta_32 = 1
    //alpha_3 = delta_32 * R_32_u1
    //beta_3 = s_23
    //#since  k(3) > j(2),
    //D_32_u1 = (g1 ** R_32_u1) * PRF_23_u1
    element_init_G1(D_32_u1,pairing);
    element_pow_zn(temp_1_G1, g1, R_32_u1);
    element_mul(D_32_u1,temp_1_G1,PRF_23_u1); 

    //#D_32_u1 sent to user
    

    //#auth1, j=1
    //g = y_1 ** x_3
    //h = g1
    //R_31_u1 = group.random(ZR)
    element_init_Zr(R_31_u1,pairing);
    element_random(R_31_u1);

    //#since k(3) > j(1) ? is true
    //gamma_3 = delta_31 = 1
    //alpha_3 = delta_31 * R_31_u1
    //beta_3 = s_13
    //#since  k(3) > j(1),
    //D_31_u1 = (g1 ** R_31_u1) * PRF_13_u1
    element_init_G1(D_31_u1,pairing);
    element_pow_zn(temp_1_G1, g1, R_31_u1);
    element_mul(D_31_u1,temp_1_G1,PRF_13_u1); 
     
    //#D_31_u1 sent to user
    
    //#u2 signup
    //#with auth1, k=1
    //#auth2, j=2
    //g = y_2 ** x_1
    //h = g1
    //R_12_u2 = group.random(ZR)
    element_init_Zr(R_12_u2,pairing);
    element_random(R_12_u2);    

    //#since k(1) > j(2) ? is false
    //gamma_1 = delta_12 = -1
    //alpha_1 = delta_12 * R_12_u2
    //beta_1 = s_12
    //#since  k(1) < j(2),
    //D_12_u2 = (g1 ** R_12_u2) * (1 / PRF_12_u2)
    element_init_G1(D_12_u2,pairing);
    element_pow_zn(temp_1_G1, g1, R_12_u2);
    element_div(D_12_u2,temp_1_G1,PRF_12_u2); 

    //#D_12_u2 sent to user
    //
    //#auth3, j=3
    //g = y_3 ** x_1
    //h = g1
    //R_13_u2 = group.random(ZR)
    element_init_Zr(R_13_u2,pairing);
    element_random(R_13_u2);

    //#since k(1) > j(3) ? is false
    //gamma_1 = delta_13 = -1
    //alpha_1 = delta_13 * R_13_u2
    //beta_1 = s_13
    //#since  k(1) < j(3),
    //D_13_u2 = (g1 ** R_13_u2) * (1 / PRF_13_u2)
    element_init_G1(D_13_u2,pairing);
    element_pow_zn(temp_1_G1, g1, R_13_u2);
    element_div(D_13_u2,temp_1_G1,PRF_13_u2); 

    //#D_13_u2 sent to user
    //
    //#with auth2, k=2
    //#auth1, j=1
    //g = y_1 ** x_2
    //h = g1
    //R_21_u2 = group.random(ZR)
    element_init_Zr(R_21_u2,pairing);
    element_random(R_21_u2);

    //#since k(2) > j(1) ? is true
    //gamma_2 = delta_21 = 1
    //alpha_2 = delta_21 * R_21_u2
    //beta_2 = s_12
    //#since  k(2) > j(1),
    //D_21_u2 = (g1 ** R_21_u2) * PRF_12_u2
    element_init_G1(D_21_u2,pairing);
    element_pow_zn(temp_1_G1, g1, R_21_u2);
    element_mul(D_21_u2,temp_1_G1,PRF_12_u2); 

    //#D_21_u2 sent to user
    //
    //#auth3, j=3
    //g = y_3 ** x_2
    //h = g1
    //R_23_u2 = group.random(ZR)
    element_init_Zr(R_23_u2,pairing);
    element_random(R_23_u2);

    //#since k(2) > j(3) ? is false
    //gamma_2 = delta_23 = -1
    //alpha_2 = delta_23 * R_23_u2
    //beta_2 = s_23
    //#since  k(2) < j(3),
    //D_23_u2 = (g1 ** R_23_u2) * (1 / PRF_23_u2)
    element_init_G1(D_23_u2,pairing);
    element_pow_zn(temp_1_G1, g1, R_23_u2);
    element_div(D_23_u2,temp_1_G1,PRF_23_u2); 

    //#D_23_u2 sent to user
    //
    //
    //#with auth3, k=3
    //#auth2, j=2
    //g = y_2 ** x_3
    //h = g1
    //R_32_u2 = group.random(ZR)
    element_init_Zr(R_32_u2,pairing);
    element_random(R_32_u2);

    //#since k(3) > j(2) ? is true
    //gamma_3 = delta_32 = 1
    //alpha_3 = delta_32 * R_32_u2
    //beta_3 = s_23
    //#since  k(3) > j(2),
    //D_32_u2 = (g1 ** R_32_u2) * PRF_23_u2
    element_init_G1(D_32_u2,pairing);
    element_pow_zn(temp_1_G1, g1, R_32_u2);
    element_mul(D_32_u2,temp_1_G1,PRF_23_u2); 

    //#D_32_u2 sent to user
    //
    //#auth3, j=1
    //g = y_1 ** x_3
    //h = g1
    //R_31_u2 = group.random(ZR)
    element_init_Zr(R_31_u2,pairing);
    element_random(R_31_u2);

    //#since k(3) > j(1) ? is true
    //gamma_3 = delta_31 = 1
    //alpha_3 = delta_31 * R_31_u2
    //beta_3 = s_13
    //#since  k(3) > j(1),
    //D_31_u2 = (g1 ** R_31_u2) * PRF_13_u2
    element_init_G1(D_31_u2,pairing);
    element_pow_zn(temp_1_G1, g1, R_31_u2);
    element_mul(D_31_u2,temp_1_G1,PRF_13_u2); 

    //#D_31_u2 sent to user
    //
    //
    //
    //
    //
    //#u3 signup
    //#with auth1, k=1
    //#auth2, j=2
    //g = y_2 ** x_1
    //h = g1
    //R_12_u3 = group.random(ZR)
    element_init_Zr(R_12_u3,pairing);
    element_random(R_12_u3);

    //#since k(1) > j(2) ? is false
    //gamma_1 = delta_12 = -1
    //alpha_1 = delta_12 * R_12_u3
    //beta_1 = s_12
    //#since  k(1) < j(2),
    //D_12_u3 = (g1 ** R_12_u3) * (1 / PRF_12_u3)
    element_init_G1(D_12_u3,pairing);
    element_pow_zn(temp_1_G1, g1, R_12_u3);
    element_div(D_12_u3,temp_1_G1,PRF_12_u3); 

    //#D_12_u2 sent to user
    //
    //#auth3, j=3
    //g = y_3 ** x_1
    //h = g1
    //R_13_u3 = group.random(ZR)
    element_init_Zr(R_13_u3,pairing);
    element_random(R_13_u3);

    //#since k(1) > j(3) ? is false
    //gamma_1 = delta_13 = -1
    //alpha_1 = delta_13 * R_13_u3
    //beta_1 = s_13
    //#since  k(1) < j(3),
    //D_13_u3 = (g1 ** R_13_u3) * (1 / PRF_13_u3)
    element_init_G1(D_13_u3,pairing);
    element_pow_zn(temp_1_G1, g1, R_13_u3);
    element_div(D_13_u3,temp_1_G1,PRF_13_u3); 

    //#D_13_u3 sent to user

    //#with auth2, k=2
    //#auth1, j=1
    //g = y_1 ** x_2
    //h = g1
    //R_21_u3 = group.random(ZR)
    element_init_Zr(R_21_u3,pairing);
    element_random(R_21_u3);

    //#since k(2) > j(1) ? is true
    //gamma_2 = delta_21 = 1
    //alpha_2 = delta_21 * R_21_u3
    //beta_2 = s_12
    //#since  k(2) > j(1),
    //D_21_u3 = (g1 ** R_21_u3) * PRF_12_u3
    element_init_G1(D_21_u3,pairing);
    element_pow_zn(temp_1_G1, g1, R_21_u3);
    element_mul(D_21_u3,temp_1_G1,PRF_12_u3); 

    //#D_21_u2 sent to user
    //
    //#auth3, j=3
    //g = y_3 ** x_2
    //h = g1
    //R_23_u3 = group.random(ZR)
    element_init_Zr(R_23_u3,pairing);
    element_random(R_23_u3);

    //#since k(2) > j(3) ? is false
    //gamma_2 = delta_23 = -1
    //alpha_2 = delta_23 * R_23_u3
    //beta_2 = s_23
    //#since  k(2) < j(3),
    //D_23_u3 = (g1 ** R_23_u3) * (1 / PRF_23_u3)
    element_init_G1(D_23_u3,pairing);
    element_pow_zn(temp_1_G1, g1, R_23_u3);
    element_div(D_23_u3,temp_1_G1,PRF_23_u3); 

    //#D_23_u2 sent to user
    //
    //
    //
    //#with auth3, k=3
    //#auth2, j=2
    //g = y_2 ** x_3
    //h = g1
    //R_32_u3 = group.random(ZR)
    element_init_Zr(R_32_u3,pairing);
    element_random(R_32_u3);

    //#since k(3) > j(2) ? is true
    //gamma_3 = delta_32 = 1
    //alpha_3 = delta_32 * R_32_u3
    //beta_3 = s_23
    //#since  k(3) > j(2),
    //D_32_u3 = (g1 ** R_32_u3) * PRF_23_u3
    element_init_G1(D_32_u3,pairing);
    element_pow_zn(temp_1_G1, g1, R_32_u3);
    element_mul(D_32_u3,temp_1_G1,PRF_23_u3); 

    //#D_32_u3 sent to user
    //
    //#auth3, j=1
    //g = y_1 ** x_3
    //h = g1
    //R_31_u3 = group.random(ZR)
    element_init_Zr(R_31_u3,pairing);
    element_random(R_31_u3);

    //#since k(3) > j(1) ? is true
    //gamma_3 = delta_31 = 1
    //alpha_3 = delta_31 * R_31_u3
    //beta_3 = s_13
    //#since  k(3) > j(1),
    //D_31_u3 = (g1 ** R_31_u3) * PRF_13_u3
    element_init_G1(D_31_u3,pairing);
    element_pow_zn(temp_1_G1, g1, R_31_u3);
    element_mul(D_31_u3,temp_1_G1,PRF_13_u3); 

    //#D_31_u3 sent to user

    //#POLYNOMIAL CALCULATION setting d_k = 2
    //#a1x + a0
    //#stored as [a1, a0]
    //#auth1
    //p_1_0_u1 = v_1 - (R_12_u1 + R_13_u1)
    element_init_Zr(p_1_0_u1, pairing);
    element_add(temp_1_Zr,R_12_u1,R_13_u1);
    element_sub(p_1_0_u1,v_1,temp_1_Zr); 
    //coeff_auth1_u1 = [group.random(ZR)]
    element_init_Zr(coeff_auth1_u1_0, pairing);
    element_random(coeff_auth1_u1_0);
    //coeff_auth1_u1.append(p_1_0_u1)
    element_init_Zr(coeff_auth1_u1_1, pairing);
    element_set(coeff_auth1_u1_1, p_1_0_u1);
   
    //p_1_0_u2 = v_1 - (R_12_u2 + R_13_u2)
    element_init_Zr(p_1_0_u2, pairing);
    element_add(temp_1_Zr,R_12_u2,R_13_u2);
    element_sub(p_1_0_u2,v_1,temp_1_Zr);
    //coeff_auth1_u2 = [group.random(ZR)]
    element_init_Zr(coeff_auth1_u2[0], pairing);
    element_random(coeff_auth1_u2[0]);
    //coeff_auth1_u2.append(p_1_0_u2)
    element_init_Zr(coeff_auth1_u2[1], pairing);
    element_set(coeff_auth1_u2[1], p_1_0_u2);

    //
    //p_1_0_u3 = v_1 - (R_12_u3 + R_13_u3)
    element_init_Zr(p_1_0_u3, pairing);
    element_add(temp_1_Zr,R_12_u3,R_13_u3);
    element_sub(p_1_0_u3,v_1,temp_1_Zr);
    //coeff_auth1_u3 = [group.random(ZR)]
    element_init_Zr(coeff_auth1_u3[0], pairing);
    element_random(coeff_auth1_u3[0]);
    //coeff_auth1_u3.append(p_1_0_u3)
    element_init_Zr(coeff_auth1_u3[1], pairing);
    element_set(coeff_auth1_u3[1], p_1_0_u3);

    //
    //
    //#auth2
    //p_2_0_u1 = v_2 - (R_21_u1 + R_23_u1)
    element_init_Zr(p_2_0_u1, pairing);
    element_add(temp_1_Zr,R_21_u1,R_23_u1);
    element_sub(p_2_0_u1,v_2,temp_1_Zr);
    //coeff_auth2_u1 = [group.random(ZR)]
    element_init_Zr(coeff_auth2_u1_0, pairing);
    element_random(coeff_auth2_u1_0);
    //coeff_auth2_u1.append(p_2_0_u1)
    element_init_Zr(coeff_auth2_u1_1, pairing);
    element_set(coeff_auth2_u1_1, p_2_0_u1);

    //p_2_0_u2 = v_2 - (R_21_u2 + R_23_u2)
    element_init_Zr(p_2_0_u2, pairing);
    element_add(temp_1_Zr,R_21_u2,R_23_u2);
    element_sub(p_2_0_u2,v_2,temp_1_Zr);
    //coeff_auth2_u2 = [group.random(ZR)]
    element_init_Zr(coeff_auth2_u2[0], pairing);
    element_random(coeff_auth2_u2[0]);
    //coeff_auth2_u2.append(p_2_0_u2)
    element_init_Zr(coeff_auth2_u2[1], pairing);
    element_set(coeff_auth2_u2[1], p_2_0_u2);

    //p_2_0_u3 = v_2 - (R_21_u3 + R_23_u3)
    element_init_Zr(p_2_0_u3, pairing);
    element_add(temp_1_Zr,R_21_u3,R_23_u3);
    element_sub(p_2_0_u3,v_2,temp_1_Zr);
    //coeff_auth2_u3 = [group.random(ZR)]
    element_init_Zr(coeff_auth2_u3[0], pairing);
    element_random(coeff_auth2_u3[0]);
    //coeff_auth2_u3.append(p_2_0_u3)
    element_init_Zr(coeff_auth2_u3[1], pairing);
    element_set(coeff_auth2_u3[1], p_2_0_u3);
    
    //#auth3
    //p_3_0_u1 = v_3 - (R_31_u1 + R_32_u1)
    element_init_Zr(p_3_0_u1, pairing);
    element_add(temp_1_Zr,R_31_u1,R_32_u1);
    element_sub(p_3_0_u1,v_3,temp_1_Zr);
    //coeff_auth3_u1 = [group.random(ZR)]
    element_init_Zr(coeff_auth3_u1_0, pairing);
    element_random(coeff_auth3_u1_0);
    //coeff_auth3_u1.append(p_3_0_u1)
    element_init_Zr(coeff_auth3_u1_1, pairing);
    element_set(coeff_auth3_u1_1, p_3_0_u1);
    //
    //p_3_0_u2 = v_3 - (R_31_u2 + R_32_u2)
    element_init_Zr(p_3_0_u2, pairing);
    element_add(temp_1_Zr,R_31_u2,R_32_u2);
    element_sub(p_3_0_u2,v_3,temp_1_Zr);
    //coeff_auth3_u2 = [group.random(ZR)]
    element_init_Zr(coeff_auth3_u2[0], pairing);
    element_random(coeff_auth3_u2[0]); 
    //coeff_auth3_u2.append(p_3_0_u2)
    element_init_Zr(coeff_auth3_u2[1], pairing);
    element_set(coeff_auth3_u2[1], p_3_0_u2);
    //
    //p_3_0_u3 = v_3 - (R_31_u3 + R_32_u3)
    element_init_Zr(p_3_0_u3, pairing);
    element_add(temp_1_Zr,R_31_u3,R_32_u3);
    element_sub(p_3_0_u3,v_3,temp_1_Zr);
    //coeff_auth3_u3 = [group.random(ZR)]
    element_init_Zr(coeff_auth3_u3[0], pairing);
    element_random(coeff_auth3_u3[0]);
    //coeff_auth3_u3.append(p_3_0_u3)
    element_init_Zr(coeff_auth3_u3[1], pairing);
    element_set(coeff_auth3_u3[1], p_3_0_u3);
    

    //#auth setting S_k_i for user 1
    //#auth1
    //S_1_1_u1 = g1 ** (p(1, coeff_auth1_u1) * (1 / t_1a1))
    element_init_G1(S_1_1_u1, pairing);
    element_mul_si(temp_1_Zr,coeff_auth1_u1_0,1);
    element_add(temp_2_Zr,temp_1_Zr,coeff_auth1_u1_1);    
    element_div(temp_3_Zr,temp_2_Zr,t_1a1);
    element_pow_zn(S_1_1_u1, g1, temp_3_Zr); 

    //S_1_2_u1 = g1 ** (p(2, coeff_auth1_u1) * (1 / t_1a2))
    element_init_G1(S_1_2_u1, pairing);
    element_mul_si(temp_1_Zr,coeff_auth1_u1_0,2);
    element_add(temp_2_Zr,temp_1_Zr,coeff_auth1_u1_1);    
    element_div(temp_3_Zr,temp_2_Zr,t_1a2);
    element_pow_zn(S_1_2_u1, g1, temp_3_Zr); 
    
    //S_1_3_u1 = g1 ** (p(3, coeff_auth1_u1) * (1 / t_1a3))
    element_init_G1(S_1_3_u1, pairing);
    element_mul_si(temp_1_Zr,coeff_auth1_u1_0,3);
    element_add(temp_2_Zr,temp_1_Zr,coeff_auth1_u1_1);    
    element_div(temp_3_Zr,temp_2_Zr,t_1a3);
    element_pow_zn(S_1_3_u1, g1, temp_3_Zr); 
        
    //S_1_4_u1 = g1 ** (p(4, coeff_auth1_u1) * (1 / t_1a4))
    element_init_G1(S_1_4_u1, pairing);
    element_mul_si(temp_1_Zr,coeff_auth1_u1_0,4);
    element_add(temp_2_Zr,temp_1_Zr,coeff_auth1_u1_1);    
    element_div(temp_3_Zr,temp_2_Zr,t_1a4);
    element_pow_zn(S_1_4_u1, g1, temp_3_Zr); 
        
    //#auth2
    //S_2_1_u1 = g1 ** (p(1, coeff_auth2_u1) * (1 / t_2a1))
    element_init_G1(S_2_1_u1, pairing);
    element_mul_si(temp_1_Zr,coeff_auth2_u1_0,1);
    element_add(temp_2_Zr,temp_1_Zr,coeff_auth2_u1_1);    
    element_div(temp_3_Zr,temp_2_Zr,t_2a1);
    element_pow_zn(S_2_1_u1, g1, temp_3_Zr); 

    //S_2_2_u1 = g1 ** (p(2, coeff_auth2_u1) * (1 / t_2a2))
    element_init_G1(S_2_2_u1, pairing);
    element_mul_si(temp_1_Zr,coeff_auth2_u1_0,2);
    element_add(temp_2_Zr,temp_1_Zr,coeff_auth2_u1_1);    
    element_div(temp_3_Zr,temp_2_Zr,t_2a2);
    element_pow_zn(S_2_2_u1, g1, temp_3_Zr); 

    //S_2_3_u1 = g1 ** (p(3, coeff_auth2_u1) * (1 / t_2a3))
    element_init_G1(S_2_3_u1, pairing);
    element_mul_si(temp_1_Zr,coeff_auth2_u1_0,3);
    element_add(temp_2_Zr,temp_1_Zr,coeff_auth2_u1_1);    
    element_div(temp_3_Zr,temp_2_Zr,t_2a3);
    element_pow_zn(S_2_3_u1, g1, temp_3_Zr); 

    //S_2_4_u1 = g1 ** (p(4, coeff_auth2_u1) * (1 / t_2a4))
    element_init_G1(S_2_4_u1, pairing);
    element_init_Zr(temp_1, pairing);
    element_init_Zr(temp_2,pairing);
    element_init_Zr(temp_3,pairing);
    element_mul_si(temp_1,coeff_auth2_u1_0,4);
    element_add(temp_2,temp_1,coeff_auth2_u1_1);    
    element_div(temp_3,temp_2,t_2a4);
    element_pow_zn(S_2_4_u1, g1, temp_3); 
    element_clear(temp_1);
    element_clear(temp_2);
    element_clear(temp_3);

    //
    //#auth3
    //S_3_1_u1 = g1 ** (p(1, coeff_auth3_u1) * (1 / t_3a1))
    element_init_G1(S_3_1_u1, pairing);
    element_init_Zr(temp_1, pairing);
    element_init_Zr(temp_2,pairing);
    element_init_Zr(temp_3,pairing);
    element_mul_si(temp_1,coeff_auth3_u1_0,1);
    element_add(temp_2,temp_1,coeff_auth3_u1_1);    
    element_div(temp_3,temp_2,t_3a1);
    element_pow_zn(S_3_1_u1, g1, temp_3); 
    element_clear(temp_1);
    element_clear(temp_2);
    element_clear(temp_3);

    //S_3_2_u1 = g1 ** (p(2, coeff_auth3_u1) * (1 / t_3a2))
    element_init_G1(S_3_2_u1, pairing);
    element_init_Zr(temp_1, pairing);
    element_init_Zr(temp_2,pairing);
    element_init_Zr(temp_3,pairing);
    element_mul_si(temp_1,coeff_auth3_u1_0,2);
    element_add(temp_2,temp_1,coeff_auth3_u1_1);    
    element_div(temp_3,temp_2,t_3a2);
    element_pow_zn(S_3_2_u1, g1, temp_3); 
    element_clear(temp_1);
    element_clear(temp_2);
    element_clear(temp_3);

    //S_3_3_u1 = g1 ** (p(3, coeff_auth3_u1) * (1 / t_3a3))
    element_init_G1(S_3_3_u1, pairing);
    element_init_Zr(temp_1, pairing);
    element_init_Zr(temp_2,pairing);
    element_init_Zr(temp_3,pairing);
    element_mul_si(temp_1,coeff_auth3_u1_0,3);
    element_add(temp_2,temp_1,coeff_auth3_u1_1);    
    element_div(temp_3,temp_2,t_3a3);
    element_pow_zn(S_3_3_u1, g1, temp_3); 
    element_clear(temp_1);
    element_clear(temp_2);
    element_clear(temp_3);

    //S_3_4_u1 = g1 ** (p(4, coeff_auth3_u1) * (1 / t_3a4))
    element_init_G1(S_3_4_u1, pairing);
    element_init_Zr(temp_1, pairing);
    element_init_Zr(temp_2,pairing);
    element_init_Zr(temp_3,pairing);
    element_mul_si(temp_1,coeff_auth3_u1_0,1);
    element_add(temp_2,temp_1,coeff_auth3_u1_1);    
    element_div(temp_3,temp_2,t_3a4);
    element_pow_zn(S_3_4_u1, g1, temp_3); 
    element_clear(temp_1);
    element_clear(temp_2);
    element_clear(temp_3);

    //
    //#auth setting S_k_i for user 2
    //#auth1
    //S_1_1_u2 = g1 ** (p(1, coeff_auth1_u2) * (1 / t_1a1))
    //S_1_2_u2 = g1 ** (p(2, coeff_auth1_u2) * (1 / t_1a2))
    //S_1_3_u2 = g1 ** (p(3, coeff_auth1_u2) * (1 / t_1a3))
    //S_1_4_u2 = g1 ** (p(4, coeff_auth1_u2) * (1 / t_1a4))
    //
    //#auth2
    //S_2_1_u2 = g1 ** (p(1, coeff_auth2_u2) * (1 / t_2a1))
    //S_2_2_u2 = g1 ** (p(2, coeff_auth2_u2) * (1 / t_2a2))
    //S_2_3_u2 = g1 ** (p(3, coeff_auth2_u2) * (1 / t_2a3))
    //S_2_4_u2 = g1 ** (p(4, coeff_auth2_u2) * (1 / t_2a4))
    //
    //#auth3
    //S_3_1_u2 = g1 ** (p(1, coeff_auth3_u2) * (1 / t_3a1))
    //S_3_2_u2 = g1 ** (p(2, coeff_auth3_u2) * (1 / t_3a2))
    //S_3_3_u2 = g1 ** (p(3, coeff_auth3_u2) * (1 / t_3a3))
    //S_3_4_u2 = g1 ** (p(4, coeff_auth3_u2) * (1 / t_3a4))
    //
    //#auth setting S_k_i for user 3
    //#auth1
    //S_1_1_u3 = g1 ** (p(1, coeff_auth1_u3) * (1 / t_1a1))
    //S_1_2_u3 = g1 ** (p(2, coeff_auth1_u3) * (1 / t_1a2))
    //S_1_3_u3 = g1 ** (p(3, coeff_auth1_u3) * (1 / t_1a3))
    //S_1_4_u3 = g1 ** (p(4, coeff_auth1_u3) * (1 / t_1a4))
    //
    //#auth2
    //S_2_1_u3 = g1 ** (p(1, coeff_auth2_u3) * (1 / t_2a1))
    //S_2_2_u3 = g1 ** (p(2, coeff_auth2_u3) * (1 / t_2a2))
    //S_2_3_u3 = g1 ** (p(3, coeff_auth2_u3) * (1 / t_2a3))
    //S_2_4_u3 = g1 ** (p(4, coeff_auth2_u3) * (1 / t_2a4))
    //
    //#auth3
    //S_3_1_u3 = g1 ** (p(1, coeff_auth3_u3) * (1 / t_3a1))
    //S_3_2_u3 = g1 ** (p(2, coeff_auth3_u3) * (1 / t_3a2))
    //S_3_3_u3 = g1 ** (p(3, coeff_auth3_u3) * (1 / t_3a3))
    //S_3_4_u3 = g1 ** (p(4, coeff_auth3_u3) * (1 / t_3a4))
    

    //#user u1 calculates D_u
    //D_u1 = D_12_u1 * D_13_u1 * D_21_u1 * D_23_u1 * D_31_u1 * D_32_u1
    element_init_G1(D_u1, pairing);  
    element_init_G1(temp_1, pairing);  
    element_init_G1(temp_2, pairing);  
    element_init_G1(temp_3, pairing);  
    element_init_G1(temp_4, pairing);  
    element_mul(temp_1, D_12_u1, D_13_u1);
    element_mul(temp_2, D_21_u1, D_23_u1);
    element_mul(temp_3, D_31_u1, D_32_u1);
    element_mul(temp_4, temp_1, temp_2);
    element_mul(D_u1, temp_4, temp_3);
    element_clear(temp_1); 
    element_clear(temp_2); 
    element_clear(temp_3); 
    element_clear(temp_4); 

    //if D_u1 == (g1 ** (R_12_u1 + R_13_u1 + R_21_u1 + R_23_u1 + R_31_u1 + R_32_u1)):
    //    print("D_u1 check succeeded")
    //else:
    //    print("D_u1 check failed")
    //
    element_init_G1(test_D_u1, pairing);
    element_init_Zr(temp_1, pairing);
    element_init_Zr(temp_2, pairing);
    element_init_Zr(temp_3, pairing);
    element_init_Zr(temp_4, pairing);
    element_init_Zr(temp_5, pairing);
    element_add(temp_1, R_12_u1, R_13_u1);
    element_add(temp_2, R_21_u1, R_23_u1);
    element_add(temp_3, R_31_u1, R_32_u1);
    element_add(temp_4, temp_1, temp_2);
    element_add(temp_5, temp_4, temp_3);
    element_pow_zn(test_D_u1, g1, temp_5);
    
    if (element_cmp(D_u1,test_D_u1) == 0) {
  //      //printf("D_u1 check succeeded\n");
    }
    else { 
        //printf("D_u1 check failed\n"); 
    }
    element_clear(temp_1);
    element_clear(temp_2);
    element_clear(temp_3);
    element_clear(temp_4);
    element_clear(temp_5);
    element_clear(test_D_u1);

    pbc_set_memory_functions(malloc, realloc, free);
    int n, result;
    struct SetupVars *setupvars = (struct SetupVars *) malloc(sizeof(struct SetupVars));
    n = element_length_in_bytes(Y);
    setupvars->Y = (unsigned char *) malloc(n*sizeof(unsigned char));
    result = element_to_bytes(setupvars->Y, Y);
    n = element_length_in_bytes(g2);
    setupvars->g2 = (unsigned char *) malloc(n*sizeof(unsigned char));
    result = element_to_bytes(setupvars->g2, g2);
    n = element_length_in_bytes(T_1a1);
    setupvars->T_1a1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->T_1a1, T_1a1);
    setupvars->T_1a2 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->T_1a2, T_1a2);
    n = element_length_in_bytes(T_2a2);
    setupvars->T_2a2 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->T_2a2, T_2a2);
    n = element_length_in_bytes(T_2a3);
    setupvars->T_2a3 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->T_2a3, T_2a3);
    n = element_length_in_bytes(T_3a1);
    setupvars->T_3a1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->T_3a1, T_3a1);
    n = element_length_in_bytes(T_3a3);
    setupvars->T_3a3 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->T_3a3, T_3a3);
    n = element_length_in_bytes(S_1_1_u1);
    setupvars->S_1_1_u1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->S_1_1_u1, S_1_1_u1);
    n = element_length_in_bytes(g1);
    setupvars->g1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->g1, g1);

    n = element_length_in_bytes(coeff_auth1_u1_0);
    setupvars->coeff_auth1_u1_0 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->coeff_auth1_u1_0, coeff_auth1_u1_0);
    n = element_length_in_bytes(coeff_auth1_u1_1);
    setupvars->coeff_auth1_u1_1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->coeff_auth1_u1_1, coeff_auth1_u1_1);

    n = element_length_in_bytes(S_1_2_u1);
    setupvars->S_1_2_u1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->S_1_2_u1, S_1_2_u1);
    n = element_length_in_bytes(S_2_2_u1);
    setupvars->S_2_2_u1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->S_2_2_u1, S_2_2_u1);

    n = element_length_in_bytes(coeff_auth2_u1_0);
    setupvars->coeff_auth2_u1_0 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->coeff_auth2_u1_0, coeff_auth2_u1_0);
    n = element_length_in_bytes(coeff_auth2_u1_1);
    setupvars->coeff_auth2_u1_1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->coeff_auth2_u1_1, coeff_auth2_u1_1);

    n = element_length_in_bytes(S_2_3_u1);
    setupvars->S_2_3_u1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->S_2_3_u1, S_2_3_u1);

    n = element_length_in_bytes(coeff_auth3_u1_0);
    setupvars->coeff_auth3_u1_0 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->coeff_auth3_u1_0, coeff_auth3_u1_0);
    n = element_length_in_bytes(coeff_auth3_u1_1);
    setupvars->coeff_auth3_u1_1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->coeff_auth3_u1_1, coeff_auth3_u1_1);


    n = element_length_in_bytes(S_3_1_u1);
    setupvars->S_3_1_u1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->S_3_1_u1, S_3_1_u1);
    n = element_length_in_bytes(S_3_3_u1);
    setupvars->S_3_3_u1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->S_3_3_u1, S_3_3_u1);
    n = element_length_in_bytes(D_u1);
    setupvars->D_u1 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->D_u1, D_u1);
    n = element_length_in_bytes(temp_1_GT);
    setupvars->temp_1_GT = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->temp_1_GT, temp_1_GT);
    n = element_length_in_bytes(temp_1_Zr);
    setupvars->temp_1_Zr = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->temp_1_Zr, temp_1_Zr);
    n = element_length_in_bytes(temp_2_Zr);
    setupvars->temp_2_Zr = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->temp_2_Zr, temp_2_Zr);
    n = element_length_in_bytes(e_g1g2);
    setupvars->e_g1g2 = (unsigned char *) malloc(n);
    element_to_bytes(setupvars->e_g1g2, e_g1g2);

    //printf("Setup Done\n");
    return setupvars;
}

struct EncryptVars* c_encrypt(struct SetupVars* setupvars) {

    //printf("encrypt start\n");
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, fopen("a.param","r"));
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing,param, count);



    element_t D_u1, test_D_u1, Q, dec_step3, decrypted_msg, auth1_pair_a1, auth1_pair_a2, P_1, temp_auth1_pair_a1, temp_auth1_pair_a2, temp_P_1, temp_auth2_pair_a3, P_2, temp_P_2, auth2_pair_a3, auth2_pair_a2, temp_auth2_pair_a2, temp_P_3, P_3, temp_auth3_pair_a3, auth3_pair_a3, temp_auth3_pair_a1, auth3_pair_a1, msg, s, E_0, E_1, C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3, L1_0_Auth1, L2_0_Auth1, L2_0_Auth2, L3_0_Auth2, L1_0_Auth3, L3_0_Auth3, S_1_1_u1, S_1_2_u1, S_1_3_u1, S_1_4_u1, S_2_1_u1, S_2_2_u1, S_2_3_u1, S_2_4_u1, S_3_1_u1, S_3_2_u1, S_3_3_u1, S_3_4_u1, S_1_1_u2, S_1_2_u2, S_1_3_u2, S_1_4_u2, S_2_1_u2, S_2_2_u2, S_2_3_u2, S_2_4_u2, S_3_1_u2, S_3_2_u2, S_3_3_u2, S_3_4_u2, S_1_1_u3, S_1_2_u3, S_1_3_u3, S_1_4_u3, S_2_1_u3, S_2_2_u3, S_2_3_u3, S_2_4_u3, S_3_1_u3, S_3_2_u3, S_3_3_u3, S_3_4_u3, coeff_auth1_u1[2], p_1_0_u1, p_1_0_u2, coeff_auth1_u2[2], p_1_0_u3, coeff_auth1_u3[2], p_2_0_u1, coeff_auth2_u1[2], p_2_0_u2, coeff_auth2_u2[2], p_2_0_u3, coeff_auth2_u3[2], p_3_0_u1, coeff_auth3_u1[2], p_3_0_u2, coeff_auth3_u2[2], p_3_0_u3, coeff_auth3_u3[2], g1, g2, x, y, r, gt, r1, u1, u2, u3, e_g1g2, s_12, s_23, s_13, v_1, Y_1, x_1, y_1, t_1a1, T_1a1, t_1a2, T_1a2, t_1a3, T_1a3, t_1a4, T_1a4, v_2, Y_2, x_2, y_2, t_2a1, T_2a1, t_2a2, T_2a2, t_2a3, T_2a3, t_2a4, T_2a4, v_3, Y_3, x_3, y_3, t_3a1, T_3a1, t_3a2, T_3a2, t_3a3, T_3a3, t_3a4, T_3a4, PRF_12_u1, PRF_12_u2, PRF_12_u3, PRF_23_u1, PRF_23_u2, PRF_23_u3, PRF_13_u1, PRF_13_u2, PRF_13_u3, Y, t1, t2, t3, h, R_12_u1, gamma_1, delta_12, alpha_1, beta_1, D_12_u1, R_13_u1, delta_13, D_13_u1, R_21_u1, gamma_2, delta_21, alpha_2, beta_2, D_21_u1, R_23_u1, delta_23, D_23_u1, R_32_u1, gamma_3, alpha_3, beta_3, delta_32, D_32_u1, R_31_u1, D_31_u1, R_12_u2, D_12_u2, R_13_u2, D_13_u2, R_21_u2, D_21_u2, R_23_u2, D_23_u2, R_32_u2, D_32_u2, R_31_u2, D_31_u2, R_12_u3, D_12_u3, R_13_u3, D_13_u3, R_21_u3, D_21_u3, R_23_u3, D_23_u3, R_32_u3, D_32_u3, R_31_u3, D_31_u3, delta_31, temp_1_Zr, temp_2_Zr, temp_3_Zr, temp_4_Zr, temp_5_Zr, temp_1_G1, temp_2_G1, temp_3_G1, temp_4_G1, temp_5_G1, temp_1_G2, temp_2_G2, temp_3_G2, temp_4_G2, temp_5_G2, temp_1_GT, temp_2_GT, temp_3_GT, temp_4_GT, temp_5_GT, temp_1, temp_2, temp_3, temp_4, temp_5;

    //printf("encrypt init start\n");
    element_init_GT(msg, pairing);
    element_init_Zr(s,pairing);
    element_init_GT(E_0, pairing);
    element_init_G2(E_1, pairing);
    element_init_G2(C_1_1, pairing);
    element_init_G2(C_1_2, pairing);
    element_init_G2(C_2_2, pairing);
    element_init_G2(C_2_3, pairing);
    element_init_G2(C_3_1, pairing);
    element_init_G2(C_3_3, pairing);
    element_init_Zr(L2_0_Auth1, pairing);
    element_init_Zr(L1_0_Auth1, pairing);
    element_init_Zr(L2_0_Auth2, pairing);
    element_init_Zr(L3_0_Auth2, pairing);
    element_init_Zr(L1_0_Auth3, pairing);
    element_init_Zr(L3_0_Auth3, pairing);

    element_init_GT(Y, pairing); 
    element_init_G2(g2, pairing);
    element_init_G2(T_1a1, pairing);
    element_init_G2(T_1a2, pairing);
    element_init_G2(T_2a2, pairing);
    element_init_G2(T_2a3, pairing);
    element_init_G2(T_3a1, pairing);
    element_init_G2(T_3a3, pairing);
    element_init_Zr(temp_1_Zr, pairing);
    element_init_Zr(temp_2_Zr, pairing);
    element_init_GT(temp_1_GT, pairing);

    element_from_bytes(Y, setupvars->Y);
    element_from_bytes(g2, setupvars->g2);
    element_from_bytes(T_1a1, setupvars->T_1a1);
    element_from_bytes(T_1a2, setupvars->T_1a2);
    element_from_bytes(T_2a2, setupvars->T_2a2);
    element_from_bytes(T_2a3, setupvars->T_2a3);
    element_from_bytes(T_3a1, setupvars->T_3a1);
    element_from_bytes(T_3a3, setupvars->T_3a3);
    element_from_bytes(temp_1_Zr, setupvars->temp_1_Zr);
    element_from_bytes(temp_2_Zr, setupvars->temp_2_Zr);
    element_from_bytes(temp_1_GT, setupvars->temp_1_GT);

    //printf("encrypt operation start\n");
    clock_t start_enc = clock(), diff_enc;
    
    //########ENCRYPTION############
    //#msg encrypted with a1,a2 attr from auth1 and a2,a3 attr from auth2 and a1,a3 attr from auth3
    //msg = group.random(GT)
    //element_from_hash(msg, "ABCDEF", 6);
    element_random(msg);
    //s = group.random(ZR)
    element_random(s);
    //E_0 = (msg * (Y ** s))
    element_pow_zn(temp_1_GT, Y, s);
    element_mul(E_0, msg, temp_1_GT);
    //E_1 = (g2 ** s)
    element_pow_zn(E_1, g2, s);     

    //#C_k_i for all k auths in system
    //C_1_1 = (T_1a1 ** s)
    element_pow_zn(C_1_1, T_1a1, s);

    //C_1_2 = (T_1a2 ** s)
    element_pow_zn(C_1_2, T_1a2, s);

    //C_2_2 = (T_2a2 ** s)
    element_pow_zn(C_2_2, T_2a2, s);

    //C_2_3 = (T_2a3 ** s)
    element_pow_zn(C_2_3, T_2a3, s);

    //C_3_1 = (T_3a1 ** s)
    element_pow_zn(C_3_1, T_3a1, s);
    //C_3_3 = (T_3a3 ** s)
    element_pow_zn(C_3_3, T_3a3, s);

    //enc_msg = (E_0, E_1, (C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3))
    

    //##############################
    //#Interpolation:
    //L1_0_Auth1 = 2
    element_set_si(L1_0_Auth1,2);
 
    //L2_0_Auth1 = -1
    element_set_si(L2_0_Auth1, -1);
 
    //L2_0_Auth2 = 3
    element_set_si(L2_0_Auth2, 3);
    
    //L3_0_Auth2 = -2
    element_set_si(L3_0_Auth2, -2);
 
    //L1_0_Auth3 = (3 * modinv(2,q)) % q
    element_set_si(temp_1_Zr,3);
    element_set_si(temp_2_Zr,2);
    element_div(L1_0_Auth3, temp_1_Zr, temp_2_Zr);
    //L3_0_Auth3 = - ((1 * modinv(2,q)) % q)
    element_set_si(temp_1_Zr,2);
    element_invert(temp_2_Zr, temp_1_Zr);
    element_neg(L3_0_Auth3, temp_2_Zr); 

    diff_enc = clock() - start_enc;
    int msec = diff_enc * 1000 / CLOCKS_PER_SEC;
    //printf("[ENCRYPTION] Time taken %d seconds %d milliseconds \n", msec/1000, msec%1000);


    int n;
    struct EncryptVars* encryptvars = (struct EncryptVars*) malloc(sizeof(struct EncryptVars));
    n = element_length_in_bytes(E_0);
    encryptvars->E_0 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->E_0, E_0);
    n = element_length_in_bytes(E_1);
    encryptvars->E_1 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->E_1, E_1);
    n = element_length_in_bytes(C_1_1);
    encryptvars->C_1_1 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->C_1_1, C_1_1);
    n = element_length_in_bytes(C_1_2);
    encryptvars->C_1_2 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->C_1_2, C_1_2);
    n = element_length_in_bytes(C_2_2);
    encryptvars->C_2_2 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->C_2_2, C_2_2);
    n = element_length_in_bytes(C_2_3);
    encryptvars->C_2_3 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->C_2_3, C_2_3);
    n = element_length_in_bytes(C_3_1);
    encryptvars->C_3_1 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->C_3_1, C_3_1);
    n = element_length_in_bytes(C_3_3);
    encryptvars->C_3_3 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->C_3_3, C_3_3);
    n = element_length_in_bytes(msg);
    encryptvars->msg = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->msg, msg);
    n = element_length_in_bytes(s);
    encryptvars->s = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->s, s);
    n = element_length_in_bytes(L1_0_Auth1);
    encryptvars->L1_0_Auth1 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->L1_0_Auth1, L1_0_Auth1);
    n = element_length_in_bytes(L2_0_Auth1);
    encryptvars->L2_0_Auth1 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->L2_0_Auth1, L2_0_Auth1);
    n = element_length_in_bytes(L2_0_Auth2);
    encryptvars->L2_0_Auth2 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->L2_0_Auth2, L2_0_Auth2);
    n = element_length_in_bytes(L3_0_Auth2);
    encryptvars->L3_0_Auth2 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->L3_0_Auth2, L3_0_Auth2);
    n = element_length_in_bytes(L1_0_Auth3);
    encryptvars->L1_0_Auth3 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->L1_0_Auth3, L1_0_Auth3);
    n = element_length_in_bytes(L3_0_Auth3);
    encryptvars->L3_0_Auth3 = (unsigned char *) malloc(n);
    element_to_bytes(encryptvars->L3_0_Auth3, L3_0_Auth3);
    return encryptvars;
}


int c_decrypt(struct SetupVars* setupvars, struct EncryptVars* encryptvars) {
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, fopen("a.param","r"));
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);



    element_t D_u1, test_D_u1, Q, dec_step3, decrypted_msg, auth1_pair_a1, auth1_pair_a2, P_1, temp_auth1_pair_a1, temp_auth1_pair_a2, temp_P_1, temp_auth2_pair_a3, P_2, temp_P_2, auth2_pair_a3, auth2_pair_a2, temp_auth2_pair_a2, temp_P_3, P_3, temp_auth3_pair_a3, auth3_pair_a3, temp_auth3_pair_a1, auth3_pair_a1, msg, s, E_0, E_1, C_1_1, C_1_2, C_2_2, C_2_3, C_3_1, C_3_3, L1_0_Auth1, L2_0_Auth1, L2_0_Auth2, L3_0_Auth2, L1_0_Auth3, L3_0_Auth3, S_1_1_u1, S_1_2_u1, S_1_3_u1, S_1_4_u1, S_2_1_u1, S_2_2_u1, S_2_3_u1, S_2_4_u1, S_3_1_u1, S_3_2_u1, S_3_3_u1, S_3_4_u1, S_1_1_u2, S_1_2_u2, S_1_3_u2, S_1_4_u2, S_2_1_u2, S_2_2_u2, S_2_3_u2, S_2_4_u2, S_3_1_u2, S_3_2_u2, S_3_3_u2, S_3_4_u2, S_1_1_u3, S_1_2_u3, S_1_3_u3, S_1_4_u3, S_2_1_u3, S_2_2_u3, S_2_3_u3, S_2_4_u3, S_3_1_u3, S_3_2_u3, S_3_3_u3, S_3_4_u3, coeff_auth1_u1_0, coeff_auth1_u1_1, p_1_0_u1, p_1_0_u2, coeff_auth1_u2[2], p_1_0_u3, coeff_auth1_u3[2], p_2_0_u1, coeff_auth2_u1_0, coeff_auth2_u1_1, p_2_0_u2, coeff_auth2_u2[2], p_2_0_u3, coeff_auth2_u3[2], p_3_0_u1, coeff_auth3_u1_0, coeff_auth3_u1_1, p_3_0_u2, coeff_auth3_u2[2], p_3_0_u3, coeff_auth3_u3[2], g1, g2, x, y, r, gt, r1, u1, u2, u3, e_g1g2, s_12, s_23, s_13, v_1, Y_1, x_1, y_1, t_1a1, T_1a1, t_1a2, T_1a2, t_1a3, T_1a3, t_1a4, T_1a4, v_2, Y_2, x_2, y_2, t_2a1, T_2a1, t_2a2, T_2a2, t_2a3, T_2a3, t_2a4, T_2a4, v_3, Y_3, x_3, y_3, t_3a1, T_3a1, t_3a2, T_3a2, t_3a3, T_3a3, t_3a4, T_3a4, PRF_12_u1, PRF_12_u2, PRF_12_u3, PRF_23_u1, PRF_23_u2, PRF_23_u3, PRF_13_u1, PRF_13_u2, PRF_13_u3, Y, t1, t2, t3, h, R_12_u1, gamma_1, delta_12, alpha_1, beta_1, D_12_u1, R_13_u1, delta_13, D_13_u1, R_21_u1, gamma_2, delta_21, alpha_2, beta_2, D_21_u1, R_23_u1, delta_23, D_23_u1, R_32_u1, gamma_3, alpha_3, beta_3, delta_32, D_32_u1, R_31_u1, D_31_u1, R_12_u2, D_12_u2, R_13_u2, D_13_u2, R_21_u2, D_21_u2, R_23_u2, D_23_u2, R_32_u2, D_32_u2, R_31_u2, D_31_u2, R_12_u3, D_12_u3, R_13_u3, D_13_u3, R_21_u3, D_21_u3, R_23_u3, D_23_u3, R_32_u3, D_32_u3, R_31_u3, D_31_u3, delta_31, temp_1_Zr, temp_2_Zr, temp_3_Zr, temp_4_Zr, temp_5_Zr, temp_1_G1, temp_2_G1, temp_3_G1, temp_4_G1, temp_5_G1, temp_1_G2, temp_2_G2, temp_3_G2, temp_4_G2, temp_5_G2, temp_1_GT, temp_2_GT, temp_3_GT, temp_4_GT, temp_5_GT, temp_1, temp_2, temp_3, temp_4, temp_5;

    element_init_GT(Y, pairing); 
    element_init_G2(g2, pairing);
    element_init_G2(T_1a1, pairing);
    element_init_G2(T_1a2, pairing);
    element_init_G2(T_2a2, pairing);
    element_init_G2(T_2a3, pairing);
    element_init_G2(T_3a1, pairing);
    element_init_G2(T_3a3, pairing);
    element_init_Zr(temp_1_Zr, pairing);
    element_init_Zr(temp_2_Zr, pairing);
    element_init_G1(S_1_1_u1, pairing);
    element_init_G1(g1, pairing);
    element_init_Zr(coeff_auth1_u1_0, pairing);
    element_init_Zr(coeff_auth1_u1_1, pairing);
    element_init_G1(S_1_2_u1, pairing);
    element_init_G1(S_2_2_u1, pairing);
    element_init_Zr(coeff_auth2_u1_0, pairing);
    element_init_Zr(coeff_auth2_u1_1, pairing);
    element_init_G1(S_2_3_u1, pairing);
    element_init_Zr(coeff_auth3_u1_0, pairing);
    element_init_Zr(coeff_auth3_u1_1, pairing);
    element_init_G1(S_3_1_u1, pairing);
    element_init_G1(S_3_3_u1, pairing);
    element_init_G1(D_u1, pairing);
    element_init_GT(temp_1_GT, pairing);
    element_init_GT(e_g1g2, pairing);
    element_from_bytes(Y, setupvars->Y);
    element_from_bytes(g2, setupvars->g2);
    element_from_bytes(T_1a1, setupvars->T_1a1);
    element_from_bytes(T_1a2, setupvars->T_1a2);
    element_from_bytes(T_2a2, setupvars->T_2a2);
    element_from_bytes(T_2a3, setupvars->T_2a3);
    element_from_bytes(T_3a1, setupvars->T_3a1);
    element_from_bytes(T_3a3, setupvars->T_3a3);
    element_from_bytes(temp_1_Zr, setupvars->temp_1_Zr);
    element_from_bytes(temp_2_Zr, setupvars->temp_2_Zr);
    element_from_bytes(S_1_1_u1, setupvars->S_1_1_u1);
    element_from_bytes(g1, setupvars->g1);
    element_from_bytes(coeff_auth1_u1_0, setupvars->coeff_auth1_u1_0);
    element_from_bytes(coeff_auth1_u1_1, setupvars->coeff_auth1_u1_1);
    element_from_bytes(S_1_2_u1, setupvars->S_1_2_u1);
    element_from_bytes(S_2_2_u1, setupvars->S_2_2_u1);
    element_from_bytes(coeff_auth2_u1_0, setupvars->coeff_auth2_u1_0);
    element_from_bytes(coeff_auth2_u1_1, setupvars->coeff_auth2_u1_1); 
    element_from_bytes(S_2_3_u1, setupvars->S_2_3_u1);
    element_from_bytes(coeff_auth3_u1_0, setupvars->coeff_auth3_u1_0);
    element_from_bytes(coeff_auth3_u1_1, setupvars->coeff_auth3_u1_1);
    element_from_bytes(S_3_1_u1, setupvars->S_3_1_u1);
    element_from_bytes(S_3_3_u1, setupvars->S_3_3_u1);
    element_from_bytes(D_u1, setupvars->D_u1);
    element_from_bytes(temp_1_GT, setupvars->temp_1_GT);
    element_from_bytes(e_g1g2, setupvars->e_g1g2);

    element_init_GT(msg, pairing);
    element_init_Zr(s,pairing);
    element_init_GT(E_0, pairing);
    element_init_G2(E_1, pairing);
    element_init_G2(C_1_1, pairing);
    element_init_G2(C_1_2, pairing);
    element_init_G2(C_2_2, pairing);
    element_init_G2(C_2_3, pairing);
    element_init_G2(C_3_1, pairing);
    element_init_G2(C_3_3, pairing);
    element_init_Zr(L2_0_Auth1, pairing);
    element_init_Zr(L1_0_Auth1, pairing);
    element_init_Zr(L2_0_Auth2, pairing);
    element_init_Zr(L3_0_Auth2, pairing);
    element_init_Zr(L1_0_Auth3, pairing);
    element_init_Zr(L3_0_Auth3, pairing);


    element_from_bytes(E_0, encryptvars->E_0);
    element_from_bytes(E_1, encryptvars->E_1);
    element_from_bytes(C_1_1, encryptvars->C_1_1);
    element_from_bytes(C_1_2, encryptvars->C_1_2);
    element_from_bytes(C_2_2, encryptvars->C_2_2);
    element_from_bytes(C_2_3, encryptvars->C_2_3);
    element_from_bytes(C_3_1, encryptvars->C_3_1);
    element_from_bytes(C_3_3, encryptvars->C_3_3);
    element_from_bytes(msg, encryptvars->msg);
    element_from_bytes(s, encryptvars->s);
    element_from_bytes(L1_0_Auth1, encryptvars->L1_0_Auth1);
    element_from_bytes(L2_0_Auth1, encryptvars->L2_0_Auth1);
    element_from_bytes(L2_0_Auth2, encryptvars->L2_0_Auth2);
    element_from_bytes(L3_0_Auth2, encryptvars->L3_0_Auth2);
    element_from_bytes(L1_0_Auth3, encryptvars->L1_0_Auth3);
    element_from_bytes(L3_0_Auth3, encryptvars->L3_0_Auth3);
//    clock_t start_dec = clock(), diff_dec;    

    //########DECRYPTION###########
    //##User 1 decrypting the msg
    //#for each auth 1, 2, 3
    //
    //#a1,a2 attr from auth1
    //#a1
    //auth1_pair_a1 = pair(S_1_1_u1, C_1_1)
    element_init_GT(auth1_pair_a1, pairing);
    element_pairing(auth1_pair_a1, S_1_1_u1, C_1_1); // auth1_pair_a1 = e(S_1_1_u1, C_1_1)

    //auth1_pair_a2 = pair(S_1_2_u1, C_1_2)
    element_init_GT(auth1_pair_a2, pairing);
    element_pairing(auth1_pair_a2, S_1_2_u1, C_1_2); // auth1_pair_a2= e(S_1_2_u1, C_1_2)

    //#interpolate values for P_1
    //P_1 = (auth1_pair_a1 ** L1_0_Auth1) * (auth1_pair_a2 ** L2_0_Auth1)
    element_init_GT(temp_1, pairing); 
    element_init_GT(temp_2, pairing);
    element_init_GT(P_1, pairing);
    element_pow_zn(temp_1, auth1_pair_a1, L1_0_Auth1); 
    element_pow_zn(temp_2, auth1_pair_a2, L2_0_Auth1); 
    element_mul(P_1, temp_1, temp_2); 
    element_clear(temp_1);
    element_clear(temp_2);

    //#a2,a3 attr from auth2
    //auth2_pair_a2 = pair(S_2_2_u1, C_2_2)
    element_init_GT(auth2_pair_a2, pairing);
    element_pairing(auth2_pair_a2, S_2_2_u1, C_2_2); // auth2_pair_a2 = e(S_2_2_u1, C_2_2)
  
    //auth2_pair_a3 = pair(S_2_3_u1, C_2_3)
    element_init_GT(auth2_pair_a3, pairing);
    element_pairing(auth2_pair_a3, S_2_3_u1, C_2_3); // auth1_pair_a2= e(S_1_2_u1, C_1_2)

    //#interpolate values for P_2
    //P_2 = (auth2_pair_a2 ** 3) * ((auth2_pair_a3 ** (-1)) ** 2)
    element_init_GT(temp_1, pairing); 
    element_init_GT(temp_2, pairing);
    element_init_GT(P_2, pairing);
    element_pow_zn(temp_1, auth2_pair_a2, L2_0_Auth2); 
    element_pow_zn(temp_2, auth2_pair_a3, L3_0_Auth2); 
    element_mul(P_2, temp_1, temp_2); 
    element_clear(temp_1);
    element_clear(temp_2);

    //#a1,a3 attr from auth3
    //auth3_pair_a1 = pair(S_3_1_u1, C_3_1)
    element_init_GT(auth3_pair_a1, pairing);
    element_pairing(auth3_pair_a1, S_3_1_u1, C_3_1); // auth3_pair_a1= e(S_3_1_u1, C_3_1)
  
    //auth3_pair_a3 = pair(S_3_3_u1, C_3_3)
    element_init_GT(auth3_pair_a3, pairing);
    element_pairing(auth3_pair_a3, S_3_3_u1, C_3_3); // auth3_pair_a3= e(S_3_3_u1, C_3_3)
  
    //#interpolate values for P_3
    //# P_3 =  (auth3_pair_a1 ** L1_0_Auth3) * (auth3_pair_a3 ** L3_0_Auth3)   
    //P_3 =  ((auth3_pair_a1 ** 3) ** modinv(2,q)) * ((auth3_pair_a3 ** -1) ** modinv(2,q))
    element_init_GT(temp_1, pairing); 
    element_init_GT(temp_2, pairing);
    element_init_GT(P_3, pairing);
    element_pow_zn(temp_1, auth3_pair_a1, L1_0_Auth3); 
    element_pow_zn(temp_2, auth3_pair_a3, L3_0_Auth3); 
    element_mul(P_3, temp_1, temp_2); 
    element_clear(temp_1);
    element_clear(temp_2);

    //Q = P_1 * P_2 * P_3
    element_init_GT(Q, pairing);
    element_init_GT(temp_1, pairing);
    element_mul(temp_1, P_1, P_2);
    element_mul(Q,temp_1, P_3);
    element_clear(temp_1);

    //dec_step3 = ((pair(D_u1, E_1)) * Q)
    element_init_GT(temp_1, pairing);
    element_init_GT(dec_step3, pairing);
    element_init_GT(decrypted_msg, pairing);
    element_pairing(temp_1, D_u1, E_1);
    element_mul(dec_step3, temp_1, Q);
    //decrypted_msg = E_0 * (1 / dec_step3)
    element_div(decrypted_msg, E_0, dec_step3); 
    element_clear(temp_1);

    //if msg == decrypted_msg:
    //    print("Message Decryption Successful")
    //else:
    //    print("Message Decryption Failed")
    if (element_cmp(msg,decrypted_msg) == 0) {
        //printf("Message Decryption Successful\n");
    }
    else { 
        //printf("Message Decryption Failed\n"); 
    }

    //diff_dec = clock() - start_dec;
    //int msec_dec = diff_dec * 1000 / CLOCKS_PER_SEC;

    //printf("[DECRYPTION] Time taken %d seconds %d milliseconds \n", msec_dec/1000, msec_dec%1000);
//    pbc_param_clear(param); 
    return 1;
}
/*
int main(int argc, char **argv) {
    struct SetupVars* setupvars = setup();
    struct EncryptVars* encryptvars = encrypt(setupvars);
    int result = decrypt(setupvars, encryptvars);
}
*/
