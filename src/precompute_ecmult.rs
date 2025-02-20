/*****************************************************************************************************
 * Copyright (c) 2013, 2014, 2017, 2021 Pieter Wuille, Andrew Poelstra, Jonas Nick, Russell O'Connor *
 * Distributed under the MIT software license, see the accompanying                                  *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.                              *
 *****************************************************************************************************/

//  #include <inttypes.h>
//  #include <stdio.h>
 
//  /* Autotools creates libsecp256k1-config.h, of which ECMULT_WINDOW_SIZE is needed.
//     ifndef guard so downstream users can define their own if they do not use autotools. */
//  #if !defined(ECMULT_WINDOW_SIZE)
//  #include "libsecp256k1-config.h"
//  #endif
 
//  #include "../include/secp256k1.h"
//  #include "assumptions.h"
//  #include "util.h"
//  #include "field_impl.h"
//  #include "group_impl.h"
//  #include "ecmult.h"
//  #include "ecmult_compute_table_impl.h"

pub mod secp256k1;
//use crate::ECMULT_TABLE_SIZE;

// pub struct secp256k1_fe {
//     /* X = sum(i=0..4, n[i]*2^(i*52)) mod p
//      * where p = 2^256 - 0x1000003D1
//      */
//    pub n : [u64; 5],
// }

// pub struct secp256k1_ge {
//     pub x: secp256k1_fe,
//     pub y: secp256k1_fe,
//     pub infinity: i32, /* whether this represents the point at infinity */
// }

// impl Default for secp256k1_ge {
//     fn default() -> Self {
//         secp256k1_ge {
//             x: secp256k1_fe { n: [0; 5] },
//             y: secp256k1_fe { n: [0; 5] },
//             infinity: 0,
//         }
//     }
// }

// pub struct secp256k1_gej {
//     x: secp256k1_fe, /* actual X: x/z^2 */
//     y: secp256k1_fe, /* actual Y: y/z^3 */
//     z: secp256k1_fe,
//     infinity: i32, /* whether this represents the point at infinity */
// }

// #[derive(Clone)]
// pub struct secp256k1_fe_storage {
//     pub n: [u64; 4],
// }


// #[derive(Clone)]
// pub struct secp256k1_ge_storage {
//     pub x: secp256k1_fe_storage,
//     pub y: secp256k1_fe_storage,
// }

// impl Default for secp256k1_ge_storage {
//     fn default() -> Self {
//         secp256k1_ge_storage {
//             x: secp256k1_fe_storage { n: [0; 4] },
//             y: secp256k1_fe_storage { n: [0; 4] },
//         }
//     }
// }

/** The number of entries a table with precomputed multiples needs to have. */
//#define ECMULT_TABLE_SIZE!(w) (1L << ((w)-2))
//#[macro_export]
// macro_rules! ECMULT_TABLE_SIZE {
//     ($w:expr) => {
//         1 << ($w - 2)
//     };
// }


// static void secp256k1_ecmult_compute_table(secp256k1_ge_storage* table, int window_g, const secp256k1_gej* gen) {
//     secp256k1_gej gj;
//     secp256k1_ge ge, dgen;
//     int j;

//     gj = *gen;
//     secp256k1_ge_set_gej_var(&ge, &gj);
//     secp256k1_ge_to_storage(&table[0], &ge);

//     secp256k1_gej_double_var(&gj, gen, NULL);
//     secp256k1_ge_set_gej_var(&dgen, &gj);

//     for (j = 1; j < ECMULT_TABLE_SIZE(window_g); ++j) {
//         secp256k1_gej_set_ge(&gj, &ge);
//         secp256k1_gej_add_ge_var(&gj, &gj, &dgen, NULL);
//         secp256k1_ge_set_gej_var(&ge, &gj);
//         secp256k1_ge_to_storage(&table[j], &ge);
//     }
// }
fn secp256k1_ecmult_compute_table(table: &mut Vec<secp256k1_ge_storage>, window_g: i32, gen: &secp256k1_gej) {
    let mut gj = gen.clone();
    let mut ge = secp256k1_ge::default();
    let mut dgen = secp256k1_ge::default();
    let mut j = 0;

    group::secp256k1_ge_set_gej_var(&mut ge, &gj);
    secp256k1_ge_to_storage(&mut table[0], &ge);

    secp256k1_gej_double_var(&mut gj, gen, None);
    secp256k1_ge_set_gej_var(&mut dgen, &gj);

    for j in 1..ECMULT_TABLE_SIZE!(window_g) {
        secp256k1_gej_set_ge(&mut gj, &ge);
        secp256k1_gej_add_ge_var(&mut gj, &gj, &dgen, None);
        secp256k1_ge_set_gej_var(&mut ge, &gj);
        secp256k1_ge_to_storage(&mut table[j as usize], &ge);
    }
}


/* Like secp256k1_ecmult_compute_table, but one for both gen and gen*2^128. */
// static void secp256k1_ecmult_compute_two_tables(secp256k1_ge_storage* table, secp256k1_ge_storage* table_128, int window_g, const secp256k1_ge* gen) {
//     secp256k1_gej gj;
//     int i;

//     secp256k1_gej_set_ge(&gj, gen);
//     secp256k1_ecmult_compute_table(table, window_g, &gj);
//     for (i = 0; i < 128; ++i) {
//         secp256k1_gej_double_var(&gj, &gj, NULL);
//     }
//     secp256k1_ecmult_compute_table(table_128, window_g, &gj);
// }

//  static void print_table(FILE *fp, const char *name, int window_g, const secp256k1_ge_storage* table) {
//      int j;
//      int i;
 
//      fprintf(fp, "const secp256k1_ge_storage %s[ECMULT_TABLE_SIZE(WINDOW_G)] = {\n", name);
//      fprintf(fp, " S(%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32
//                    ",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32")\n",
//                  SECP256K1_GE_STORAGE_CONST_GET(table[0]));
 
//      j = 1;
//      for(i = 3; i <= window_g; ++i) {
//          fprintf(fp, "#if WINDOW_G > %d\n", i-1);
//          for(;j < ECMULT_TABLE_SIZE(i); ++j) {
//              fprintf(fp, ",S(%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32
//                            ",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32")\n",
//                          SECP256K1_GE_STORAGE_CONST_GET(table[j]));
//          }
//          fprintf(fp, "#endif\n");
//      }
//      fprintf(fp, "};\n");
//  }

fn print_table(fp: &mut std::fs::File, name: &str, window_g: i32, table: &Vec<secp256k1_ge_storage>) {
    let mut j = 1;
    let mut i = 3;
    let table_size = table.len();
    let mut table_iter = table.iter();
    let first = table_iter.next().unwrap();
    let first_const = SECP256K1_GE_STORAGE_CONST_GET(*first);
    writeln!(fp, "const secp256k1_ge_storage {}[ECMULT_TABLE_SIZE(WINDOW_G)] = {{", name);
    writeln!(fp, " S(0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x}),\n",
        first_const.0, first_const.1, first_const.2, first_const.3, first_const.4, first_const.5, first_const.6, first_const.7,
        first_const.8, first_const.9, first_const.10, first_const.11, first_const.12, first_const.13, first_const.14, first_const.15);

    while i <= window_g {
        writeln!(fp, "#if WINDOW_G > {}", i-1);
        for _ in 0..ECMULT_TABLE_SIZE!(i) {
            let next = table_iter.next().unwrap();
            let next_const = SECP256K1_GE_STORAGE_CONST_GET(*next);
            writeln!(fp, " S(0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x},0x{:08x}),\n",
                next_const.0, next_const.1, next_const.2, next_const.3, next_const.4, next_const.5, next_const.6, next_const.7,
                next_const.8, next_const.9, next_const.10, next_const.11, next_const.12, next_const.13, next_const.14, next_const.15);

        }
        writeln!(fp, "}}\n");
    }
}

 
//  static void print_two_tables(FILE *fp, int window_g) {
//      secp256k1_ge_storage* table = malloc(ECMULT_TABLE_SIZE(window_g) * sizeof(secp256k1_ge_storage));
//      secp256k1_ge_storage* table_128 = malloc(ECMULT_TABLE_SIZE(window_g) * sizeof(secp256k1_ge_storage));
 
//      secp256k1_ecmult_compute_two_tables(table, table_128, window_g, &secp256k1_ge_const_g);
 
//      print_table(fp, "secp256k1_pre_g", window_g, table);
//      print_table(fp, "secp256k1_pre_g_128", window_g, table_128);
 
//      free(table);
//      free(table_128);
//  }
 
fn print_two_tables(fp: &mut std::fs::File, window_g: i32) {
    let table = vec![secp256k1_ge_storage::default(); ECMULT_TABLE_SIZE!(window_g) as usize];
    let table_128 = vec![secp256k1_ge_storage::default(); ECMULT_TABLE_SIZE!(window_g) as usize];
    secp256k1_ecmult_compute_two_tables(&mut table, &mut table_128, window_g, &secp256k1_ge_const_g);
    print_table(fp, "secp256k1_pre_g", window_g, &table);
    print_table(fp, "secp256k1_pre_g_128", window_g, &table_128);
} 

//  int main(void) {
//      /* Always compute all tables for window sizes up to 15. */
//      int window_g = (ECMULT_WINDOW_SIZE < 15) ? 15 : ECMULT_WINDOW_SIZE;
//      FILE* fp;
 
//      fp = fopen("src/precomputed_ecmult.c","w");
//      if (fp == NULL) {
//          fprintf(stderr, "Could not open src/precomputed_ecmult.h for writing!\n");
//          return -1;
//      }
 
//      fprintf(fp, "/* This file was automatically generated by precompute_ecmult. */\n");
//      fprintf(fp, "/* This file contains an array secp256k1_pre_g with odd multiples of the base point G and\n");
//      fprintf(fp, " * an array secp256k1_pre_g_128 with odd multiples of 2^128*G for accelerating the computation of a*P + b*G.\n");
//      fprintf(fp, " */\n");
//      fprintf(fp, "#if defined HAVE_CONFIG_H\n");
//      fprintf(fp, "#    include \"libsecp256k1-config.h\"\n");
//      fprintf(fp, "#endif\n");
//      fprintf(fp, "#include \"../include/secp256k1.h\"\n");
//      fprintf(fp, "#include \"group.h\"\n");
//      fprintf(fp, "#include \"ecmult.h\"\n");
//      fprintf(fp, "#include \"precomputed_ecmult.h\"\n");
//      fprintf(fp, "#define S(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) SECP256K1_GE_STORAGE_CONST(0x##a##u,0x##b##u,0x##c##u,0x##d##u,0x##e##u,0x##f##u,0x##g##u,0x##h##u,0x##i##u,0x##j##u,0x##k##u,0x##l##u,0x##m##u,0x##n##u,0x##o##u,0x##p##u)\n");
//      fprintf(fp, "#if ECMULT_WINDOW_SIZE > %d\n", window_g);
//      fprintf(fp, "   #error configuration mismatch, invalid ECMULT_WINDOW_SIZE. Try deleting precomputed_ecmult.c before the build.\n");
//      fprintf(fp, "#endif\n");
//      fprintf(fp, "#ifdef EXHAUSTIVE_TEST_ORDER\n");
//      fprintf(fp, "#    error Cannot compile precomputed_ecmult.c in exhaustive test mode\n");
//      fprintf(fp, "#endif /* EXHAUSTIVE_TEST_ORDER */\n");
//      fprintf(fp, "#define WINDOW_G ECMULT_WINDOW_SIZE\n");
 
//      print_two_tables(fp, window_g);
 
//      fprintf(fp, "#undef S\n");
//      fclose(fp);
 
//      return 0;
//  }