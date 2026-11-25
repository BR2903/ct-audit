#!/usr/bin/env bash
# Matriz compiladores x flags sobre mlkem-native (C portable) y agrega una fila
# por configuración a resultados.csv (mismas columnas que matriz.sh).
#
# Uso:   ./matriz_mn.sh <rol> <commit|rama> "<niveles>" "<compiladores>" [iteraciones]
# Niveles: 512 768 1024
# Ej.:   ./matriz_mn.sh auditoria main "512 768 1024" "clang-18 gcc-14"
# Variables opcionales:
#   FLAGS="-O2 -flto;-Os"   flags personalizados separados por ; (como en matriz.sh)
#   BARRIER=volatile        usa el value barrier de variable global volatile
#                           (MLK_CONFIG_NO_ASM_VALUE_BARRIER) en vez del de asm
#   CANARIO=1               control positivo: compila una COPIA TEMPORAL del código
#                           con un branch secreto inyectado a propósito en decaps.
#   ABLACION=1              quita los value barriers de assembly de mlkem/src/verify.h
#                           (las funciones mlk_value_barrier_*) en una COPIA TEMPORAL.
#   CANARIO y ABLACION nunca modifican el repositorio de mlkem-native.

set -u
if [ $# -lt 4 ]; then
  sed -n '2,18p' "$0"; exit 1
fi
ROL=$1; REF=$2; LVLS=$3; CCS=$4; ITERS=${5:-10}
ROOT=${CT_ROOT:-$HOME/ct-audit}
CSV=$ROOT/resultados.csv
HARNESS=$ROOT/harness_mlkem_native.c
REPO=$ROOT/mlkem-native

cd "$REPO" && git checkout -q "$REF" || { echo "No pude hacer checkout de $REF"; exit 1; }
COMMIT=$(git rev-parse --short HEAD)
SRCDIR=$REPO/mlkem

BARRIER=${BARRIER:-asm}
EXTRA=""
[ "$BARRIER" = "volatile" ] && EXTRA="-DMLK_CONFIG_NO_ASM_VALUE_BARRIER"
NOTA="barrier=$BARRIER"

if [ "${CANARIO:-0}" = "1" ] || [ "${ABLACION:-0}" = "1" ]; then
  TMP=$(mktemp -d)
  cp -r "$REPO/mlkem" "$TMP/"
  SRCDIR=$TMP/mlkem
fi

if [ "${ABLACION:-0}" = "1" ]; then
  N=$(grep -c '__asm__ volatile("" : "+r"(b));' "$TMP/mlkem/src/verify.h")
  sed -i 's|__asm__ volatile("" : "+r"(b));|/* ABLACION: value barrier eliminado */|' "$TMP/mlkem/src/verify.h"
  [ "$N" -gt 0 ] && ! grep -q '__asm__ volatile("" : "+r"(b));' "$TMP/mlkem/src/verify.h" \
    || { echo "No se pudieron quitar los value barriers"; exit 1; }
  echo "Ablación: $N value barriers de assembly eliminados (copia temporal)"
  NOTA="$NOTA;ablacion_sin_barrier"
fi

if [ "${CANARIO:-0}" = "1" ]; then
  sed -i '/fail = mlk_ct_memcmp(ct, tmp, MLKEM_INDCCA_CIPHERTEXTBYTES);/a\  { static volatile int canario; if (fail) canario++; } /* CANARIO */' \
      "$TMP/mlkem/src/kem.c"
  grep -q CANARIO "$TMP/mlkem/src/kem.c" || { echo "No se pudo inyectar el canario"; exit 1; }
  NOTA="$NOTA;canario"
fi

if [ ! -f "$CSV" ]; then
  echo "fecha,libreria,commit,rol,operacion,kyber_k,compilador,version_compilador,flags,harness,iteraciones,decaps_ok,decaps_total,reportes_valgrind,ubicaciones_fuga,detalle_ubicaciones,notas" > "$CSV"
fi

FECHA=$(date -I)
for lvl in $LVLS; do
  k=$((lvl / 256))
  for cc in $CCS; do
    if ! command -v "$cc" >/dev/null; then echo "Saltando $cc (no instalado)"; continue; fi
    VER=$("$cc" --version 2>/dev/null | head -1)
    case $cc in gcc*) NOVEC="-O2 -fno-tree-vectorize" ;; *) NOVEC="-O2 -fno-vectorize" ;; esac
    if [ -n "${FLAGS:-}" ]; then
      IFS=';' read -r -a OPTS <<< "$FLAGS"
    else
      OPTS=("-O0" "-O1" "-O2" "-O3" "-Os" "$NOVEC")
    fi
    for opt in "${OPTS[@]}"; do
      bin=/tmp/mn_${COMMIT}_${lvl}_${cc}_${BARRIER}_$(echo "$opt" | tr -d ' -' | tr '=' '_')

      if ! $cc $opt -g $EXTRA -DMLK_CONFIG_PARAMETER_SET=$lvl -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem \
           -I"$SRCDIR" "$HARNESS" "$SRCDIR"/src/*.c "$SRCDIR"/src/fips202/*.c -o "$bin" 2>/tmp/cc.err; then
        echo "$FECHA,mlkem-native,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_mlkem_native,$ITERS,,,,,,\"error de compilación;$NOTA\"" >> "$CSV"
        echo "ML-KEM-$lvl $cc [$opt] -> ERROR DE COMPILACIÓN (ver /tmp/cc.err)"
        continue
      fi

      OUT=$(valgrind -q "$bin" "$ITERS" 2>"$bin.vg")
      OK=$(echo "$OUT"  | sed -n 's/.*: \([0-9]*\)\/[0-9]* decaps.*/\1/p')
      TOT=$(echo "$OUT" | sed -n 's/.*: [0-9]*\/\([0-9]*\) decaps.*/\1/p')
      if [ -z "$OK" ] || grep -q "Process terminating" "$bin.vg"; then
        MOTIVO=$(grep -m1 -o "signal [0-9]* ([A-Z]*)" "$bin.vg")
        echo "$FECHA,mlkem-native,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_mlkem_native,$ITERS,,,,,,\"error de ejecución ${MOTIVO};$NOTA\"" >> "$CSV"
        echo "ML-KEM-$lvl $cc [$opt] -> ERROR DE EJECUCIÓN ${MOTIVO} (ver $bin.vg)"
        continue
      fi
      REP=$(grep -c 'Conditional jump\|Use of uninit' "$bin.vg")
      LOCS=$(grep -A1 'Conditional jump\|Use of uninit' "$bin.vg" | grep ' at ' | sed 's/.*: //' | sort -u)
      N=$(printf '%s' "$LOCS" | grep -c .)
      DET=$(printf '%s' "$LOCS" | tr '\n' ';' | sed 's/;$//')

      echo "$FECHA,mlkem-native,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_mlkem_native,$ITERS,$OK,$TOT,$REP,$N,\"$DET\",\"$NOTA\"" >> "$CSV"
      echo "ML-KEM-$lvl $cc [$opt] -> decaps $OK/$TOT | reportes $REP | ubicaciones con fuga: $N ${DET:+-> $DET}"
    done
  done
done
[ -n "${TMP:-}" ] && rm -rf "$TMP"
echo "Listo. Resultados agregados a $CSV"
