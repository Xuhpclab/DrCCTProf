#include "dr_api.h"

// TODO: search for dynamorio interface to obtain element witdh of a SIMD operation
// As the dynamorio did not provide function to obtain SIMD operation width of each element, Zerospy mannually implements with a lookup table
#ifdef ARM_CCTLIB

#ifdef ARM

uint32_t
FloatOperandSizeTable(instr_t *instr, opnd_t opnd)
{
    uint size = opnd_size_in_bytes(opnd_get_size(opnd));
    if(size!=16 && size!=32 && size!=64) {
        // ignore those non-vectorized instructions (not start with OP_v*)
        return size;
    }
    int opc = instr_get_opcode(instr);

    switch (opc) {

    /* convert instructions */
    case OP_vcvt_f32_f16:
    case OP_vcvtb_f32_f16:
    case OP_vcvtb_f64_f16:
    case OP_vcvtt_f32_f16:
    case OP_vcvtt_f64_f16:
    /* end of convert instructions */
    case OP_vrev16_16:  // ?
    case OP_vrev32_16:  // ?
    case OP_vrev64_16:  // ?
    case OP_vtrn_16:  // ?
    case OP_vtst_16:  // ?
    case OP_vuzp_16:  // ?
    case OP_vzip_16:  // ?
        return 2;

    case OP_vabs_f32:
    case OP_vacge_f32:
    case OP_vacgt_f32:
    case OP_vadd_f32:
    case OP_vceq_f32:
    case OP_vcge_f32:
    case OP_vcgt_f32:
    case OP_vcle_f32:
    case OP_vclt_f32:
    case OP_vcmp_f32:
    case OP_vcmpe_f32:
    /* convert instructions */
    case OP_vcvt_f16_f32:
    case OP_vcvt_f64_f32:
    case OP_vcvt_s16_f32:
    case OP_vcvt_s32_f32:
    case OP_vcvt_u16_f32:
    case OP_vcvt_u32_f32:
    case OP_vcvta_s32_f32:
    case OP_vcvta_u32_f32:
    case OP_vcvtb_f16_f32:
    case OP_vcvtm_s32_f32:
    case OP_vcvtm_u32_f32:
    case OP_vcvtn_s32_f32:
    case OP_vcvtn_u32_f32:
    case OP_vcvtp_s32_f32:
    case OP_vcvtp_u32_f32:
    case OP_vcvtr_s32_f32:
    case OP_vcvtr_u32_f32:
    case OP_vcvtt_f16_f32:
    /* end of convert instructions */
    case OP_vdiv_f32:
    case OP_vfma_f32:
    case OP_vfms_f32:
    case OP_vfnma_f32:
    case OP_vfnms_f32:
    case OP_vmax_f32:
    case OP_vmaxnm_f32:
    case OP_vmin_f32:
    case OP_vminnm_f32:
    case OP_vmla_f32:
    case OP_vmls_f32:
    case OP_vmov_f32:
    case OP_vmul_f32:
    case OP_vneg_f32:
    case OP_vnmla_f32:
    case OP_vnmls_f32:
    case OP_vnmul_f32:
    case OP_vpadd_f32:
    case OP_vpmax_f32:
    case OP_vpmin_f32:
    case OP_vrecpe_f32:
    case OP_vrecps_f32:
    case OP_vrev32_32:  // ?
    case OP_vrev64_32:  // ?
    case OP_vrinta_f32_f32:  // ?
    case OP_vrintm_f32_f32:  // ?
    case OP_vrintn_f32_f32:  // ?
    case OP_vrintp_f32_f32:  // ?
    case OP_vrintr_f32:  // ?
    case OP_vrintx_f32:  // ?
    case OP_vrintx_f32_f32:  // ?
    case OP_vrintz_f32:  // ?
    case OP_vrintz_f32_f32:  // ?
    case OP_vrsqrte_f32:
    case OP_vrsqrts_f32:
    case OP_vsel_eq_f32:
    case OP_vsel_ge_f32:
    case OP_vsel_gt_f32:
    case OP_vsel_vs_f32:
    case OP_vsqrt_f32:
    case OP_vsub_f32:
    case OP_vtrn_32:  // ?
    case OP_vtst_32:  // ?
    case OP_vuzp_32:  // ?
    case OP_vzip_32:  // ?
        return 4;

    case OP_vabs_f64:
    case OP_vadd_f64:
    case OP_vcmp_f64:
    case OP_vcmpe_f64:
    /* convert instructions */
    case OP_vcvt_f32_f64:
    case OP_vcvt_s16_f64:
    case OP_vcvt_s32_f64:
    case OP_vcvt_u16_f64:
    case OP_vcvt_u32_f64:
    case OP_vcvta_s32_f64:
    case OP_vcvta_u32_f64:
    case OP_vcvtb_f16_f64:
    case OP_vcvtm_s32_f64:
    case OP_vcvtm_u32_f64:
    case OP_vcvtn_s32_f64:
    case OP_vcvtn_u32_f64:
    case OP_vcvtp_s32_f64:
    case OP_vcvtp_u32_f64:
    case OP_vcvtr_s32_f64:
    case OP_vcvtr_u32_f64:
    case OP_vcvtt_f16_f64:
    /* end of convert instructions */
    case OP_vdiv_f64:
    case OP_vfma_f64:
    case OP_vfms_f64:
    case OP_vfnma_f64:
    case OP_vfnms_f64:
    case OP_vmaxnm_f64:
    case OP_vminnm_f64:
    case OP_vmla_f64:
    case OP_vmls_f64:
    case OP_vmov_f64:
    case OP_vmul_f64:
    case OP_vneg_f64:
    case OP_vnmla_f64:
    case OP_vnmls_f64:
    case OP_vnmul_f64:
    case OP_vrinta_f64_f64:  // ?
    case OP_vrintm_f64_f64:  // ?
    case OP_vrintn_f64_f64:  // ?
    case OP_vrintp_f64_f64:  // ?
    case OP_vrintr_f64:  // ?
    case OP_vrintx_f64:  // ?
    case OP_vrintz_f64:  // ?
    case OP_vsel_eq_f64:
    case OP_vsel_ge_f64:
    case OP_vsel_gt_f64:
    case OP_vsel_vs_f64:
    case OP_vsqrt_f64:
    case OP_vsub_f64:
        return 8;

    default: return 0;
    }
}

#else

uint32_t
FloatOperandSizeTable(instr_t *instr, opnd_t opnd)
{
    uint size = opnd_size_in_bytes(opnd_get_size(opnd));
    if(size!=16 && size!=32 && size!=64) {
        // ignore those non-vectorized instructions (not start with OP_v*)
        return size;
    }

    opnd_t width = instr_get_src(instr, instr_num_srcs(instr) - 1);
    if (!opnd_is_immed_int(width)) return size;

    switch (opnd_get_immed_int(width)) {
    case VECTOR_ELEM_WIDTH_HALF:
        return 2;
    case VECTOR_ELEM_WIDTH_SINGLE:
        return 4;
    case VECTOR_ELEM_WIDTH_DOUBLE:
        return 8;
    default:
        return 0;
    }
}

#endif

bool instr_is_ignorable(instr_t *ins) {
    return false;
}

#else

uint32_t
FloatOperandSizeTable(instr_t *instr, opnd_t opnd)
{
    uint size = opnd_size_in_bytes(opnd_get_size(opnd));
    if(size!=16 && size!=32 && size!=64) {
        // ignore those non-vectorized instructions (not start with OP_v*)
        return size;
    }
    int opc = instr_get_opcode(instr);

    switch (opc) {

    // TODO: packed 128-bit floating-point, treat them as two double floating points
    case OP_vinsertf128:
    case OP_vextractf128:
    case OP_vbroadcastf128:
    case OP_vperm2f128:
        return 8;
        //return 16;

    case OP_vmovss:
    case OP_vmovups:
    case OP_vmovlps:
    case OP_vmovsldup:
    case OP_vmovhps:
    case OP_vmovshdup:
    case OP_vmovaps:
    case OP_vmovntps:
    case OP_unpcklps:
    case OP_unpckhps:
    case OP_vunpcklps:
    case OP_vunpckhps:
    case OP_extractps:
    case OP_insertps:
    case OP_vextractps:
    case OP_vinsertps:
    case OP_vbroadcastss:
    case OP_vpermilps:
    case OP_vmaskmovps:
    case OP_vshufps:
        return 4;

    case OP_vmovsd:
    case OP_vmovupd:
    case OP_vmovlpd:
    case OP_vmovddup:
    case OP_vmovhpd:
    case OP_vmovapd:
    case OP_vmovntpd:
    case OP_unpcklpd:
    case OP_unpckhpd:
    case OP_vunpcklpd:
    case OP_vunpckhpd:
    case OP_vbroadcastsd:
    case OP_vpermilpd:
    case OP_vmaskmovpd:
    case OP_vshufpd:
        return 8;

    /* Ignore Convert instructions */

    /* SSE3/3D-Now!/SSE4 */
    case OP_haddps:
    case OP_hsubps:
    case OP_addsubps:
    case OP_femms:
    case OP_movntss:
    case OP_blendvps:
    case OP_roundps:
    case OP_roundss:
    case OP_blendps:
    case OP_dpps:
        return 4;

    case OP_haddpd:
    case OP_hsubpd:
    case OP_addsubpd:
    case OP_movntsd:
    case OP_blendvpd:
    case OP_roundpd:
    case OP_roundsd:
    case OP_blendpd:
    case OP_dppd:
        return 8;

    /* AVX */
    case OP_vucomiss:
    case OP_vcomiss:
    case OP_vmovmskps:
    case OP_vsqrtps:
    case OP_vsqrtss:
    case OP_vrsqrtps:
    case OP_vrsqrtss:
    case OP_vrcpps:
    case OP_vrcpss:
    case OP_vandps:
    case OP_vandnps:
    case OP_vorps:
    case OP_vxorps:
    case OP_vaddps:
    case OP_vaddss:
    case OP_vmulps:
    case OP_vmulss:
    case OP_vsubss:
    case OP_vsubps:
    case OP_vminps:
    case OP_vminss:
    case OP_vdivps:
    case OP_vdivss:
    case OP_vmaxps:
    case OP_vmaxss:
    case OP_vcmpps:
    case OP_vcmpss:
    case OP_vhaddps:
    case OP_vhsubps:
    case OP_vaddsubps:
    case OP_vblendvps:
    case OP_vroundps:
    case OP_vroundss:
    case OP_vblendps:
    case OP_vdpps:
    case OP_vtestps:
        return 4;

    case OP_vucomisd:
    case OP_vcomisd:
    case OP_vmovmskpd:
    case OP_vsqrtpd:
    case OP_vsqrtsd:
    case OP_vandpd:
    case OP_vandnpd:
    case OP_vorpd:
    case OP_vxorpd:
    case OP_vaddpd:
    case OP_vaddsd:
    case OP_vmulpd:
    case OP_vmulsd:
    case OP_vsubpd:
    case OP_vsubsd:
    case OP_vminpd:
    case OP_vminsd:
    case OP_vdivpd:
    case OP_vdivsd:
    case OP_vmaxpd:
    case OP_vmaxsd:
    case OP_vcmppd:
    case OP_vcmpsd:
    case OP_vhaddpd:
    case OP_vhsubpd:
    case OP_vaddsubpd:
    case OP_vblendvpd:
    case OP_vroundpd:
    case OP_vroundsd:
    case OP_vblendpd:
    case OP_vdppd:
    case OP_vtestpd:
        return 8;

    /* SSE packed instruction */
    case OP_addpd:
    case OP_mulpd:
        return 8;

    case OP_addps:
    case OP_mulps:
        return 4;

    /* FMA */
    case OP_vfmadd132ps:
    case OP_vfmadd213ps:
    case OP_vfmadd231ps:
    case OP_vfmadd132ss:
    case OP_vfmadd213ss:
    case OP_vfmadd231ss:
    case OP_vfmaddsub132ps:
    case OP_vfmaddsub213ps:
    case OP_vfmaddsub231ps:
    case OP_vfmsubadd132ps:
    case OP_vfmsubadd213ps:
    case OP_vfmsubadd231ps:
    case OP_vfmsub132ps:
    case OP_vfmsub213ps:
    case OP_vfmsub231ps:
    case OP_vfmsub132ss:
    case OP_vfmsub213ss:
    case OP_vfnmadd132ps:
    case OP_vfnmadd213ps:
    case OP_vfnmadd231ps:
    case OP_vfnmadd132ss:
    case OP_vfnmadd213ss:
    case OP_vfnmadd231ss:
    case OP_vfnmsub213ps:
    case OP_vfnmsub132ss:
    case OP_vfnmsub213ss:
    case OP_vfnmsub231ss:
        return 4;

    case OP_vfmadd132pd:
    case OP_vfmadd213pd:
    case OP_vfmadd231pd:
    case OP_vfmadd132sd:
    case OP_vfmadd213sd:
    case OP_vfmadd231sd:
    case OP_vfmaddsub132pd:
    case OP_vfmaddsub213pd:
    case OP_vfmaddsub231pd:
    case OP_vfmsubadd132pd:
    case OP_vfmsubadd213pd:
    case OP_vfmsubadd231pd:
    case OP_vfmsub132pd:
    case OP_vfmsub213pd:
    case OP_vfmsub231pd:
    case OP_vfmsub132sd:
    case OP_vfmsub213sd:
    case OP_vfmsub231ss:
    case OP_vfmsub231sd:
    case OP_vfnmadd132pd:
    case OP_vfnmadd213pd:
    case OP_vfnmadd231pd:
    case OP_vfnmadd132sd:
    case OP_vfnmadd213sd:
    case OP_vfnmadd231sd:
    case OP_vfnmsub132ps:
    case OP_vfnmsub132pd:
    case OP_vfnmsub213pd:
    case OP_vfnmsub231ps:
    case OP_vfnmsub231pd:
    case OP_vfnmsub132sd:
    case OP_vfnmsub213sd:
    case OP_vfnmsub231sd:
        return 8;

    default: return 0;
    }
}

// Currently, we mark x87 control instructions handling FPU states are ignorable (not insterested)
bool instr_is_ignorable(instr_t *ins) {
    int opc = instr_get_opcode(ins);
    switch (opc) {
        case OP_fldenv:
        case OP_fldcw:
        case OP_fnstenv:
        case OP_fnstcw:
        case OP_fnsave:
        case OP_fnstsw:
        case OP_frstor:
            return true;
        default:
            return false;
    }
    return false;
}

#endif
