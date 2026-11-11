#!/usr/bin/env bash
# Matriz compiladores x flags sobre ML-KEM de PQClean (implementación "clean") y agrega
# una fila por configuración a resultados.csv (mismas columnas que matriz.sh).
#
# Uso:   ./matriz_pqc.sh <rol> <commit|rama> "<niveles>" "<compiladores>" [iteraciones]
# Niveles: 512 768 1024
# Ej.:   ./matriz_pqc.sh auditoria 0586a824 "512 768 1024" "clang-18 gcc-14"
# Variables opcionales:
#   FLAGS="-O2 -flto;-Os"  flags personalizados separados por ; (como en matriz.sh)
#   CANARIO=1              control positivo: branch secreto inyectado en decaps
#   ABLACION=1             quita el value barrier (PQCLEAN_PREVENT_BRANCH_HACK) de cmov
#   CANARIO y ABLACION trabajan sobre una COPIA TEMPORAL; el repositorio no se modifica.

set -u
if [ $# -lt 4 ]; then
  sed -n '2,15p' "$0"; exit 1
fi
ROL=$1; REF=$2; LVLS=$3; CCS=$4; ITERS=${5:-10}
ROOT=${CT_ROOT:-$HOME/ct-audit}
CSV=$ROOT/resultados.csv
HARNESS=$ROOT/harness_pqclean.c
REPO=$ROOT/PQClean

cd "$REPO" && git checkout -q "$REF" || { echo "No pude hacer checkout de $REF"; exit 1; }
COMMIT=$(git rev-parse --short=8 HEAD)
BASE=$REPO
NOTA="original"

if [ "${CANARIO:-0}" = "1" ] || [ "${ABLACION:-0}" = "1" ]; then
  TMP=$(mktemp -d)
  mkdir -p "$TMP/crypto_kem"
  cp -r "$REPO/common" "$TMP/"
  for lvl in $LVLS; do cp -r "$REPO/crypto_kem/ml-kem-$lvl" "$TMP/crypto_kem/"; done
  BASE=$TMP
  NOTA=""
  for lvl in $LVLS; do
    D=$TMP/crypto_kem/ml-kem-$lvl/clean
    if [ "${CANARIO:-0}" = "1" ]; then
      sed -i "/fail = PQCLEAN_MLKEM${lvl}_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);/a\    { static volatile int canario; if (fail) canario++; } /* CANARIO */" "$D/kem.c"
      grep -q CANARIO "$D/kem.c" || { echo "No se pudo inyectar el canario en ML-KEM-$lvl"; exit 1; }
    fi
    if [ "${ABLACION:-0}" = "1" ]; then
      sed -i 's/^    PQCLEAN_PREVENT_BRANCH_HACK(b);/    \/* ABLACION: barrier eliminado *\//' "$D/verify.c"
      grep -q ABLACION "$D/verify.c" || { echo "No se pudo quitar el barrier en ML-KEM-$lvl"; exit 1; }
    fi
  done
  [ "${CANARIO:-0}" = "1" ] && NOTA="canario"
  [ "${ABLACION:-0}" = "1" ] && NOTA="${NOTA:+$NOTA;}ablacion_sin_barrier"
fi

if [ ! -f "$CSV" ]; then
  echo "fecha,libreria,commit,rol,operacion,kyber_k,compilador,version_compilador,flags,harness,iteraciones,decaps_ok,decaps_total,reportes_valgrind,ubicaciones_fuga,detalle_ubicaciones,notas" > "$CSV"
fi

FECHA=$(date -I)
for lvl in $LVLS; do
  k=$((lvl / 256))
  D=$BASE/crypto_kem/ml-kem-$lvl/clean
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
      bin=/tmp/pqc_${COMMIT}_${lvl}_${cc}_$(echo "$opt" | tr -d ' -' | tr '=' '_')

      if ! $cc $opt -g -DLVL=$lvl -I"$D" -I"$BASE/common" "$HARNESS" "$D"/*.c \
           "$BASE/common/fips202.c" "$BASE/common/randombytes.c" -o "$bin" 2>/tmp/cc.err; then
        echo "$FECHA,pqclean,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_pqclean,$ITERS,,,,,,\"error de compilación;$NOTA\"" >> "$CSV"
        echo "ML-KEM-$lvl $cc [$opt] -> ERROR DE COMPILACIÓN (ver /tmp/cc.err)"
        continue
      fi

      OUT=$(valgrind -q "$bin" "$ITERS" 2>"$bin.vg")
      OK=$(echo "$OUT"  | sed -n 's/.*: \([0-9]*\)\/[0-9]* decaps.*/\1/p')
      TOT=$(echo "$OUT" | sed -n 's/.*: [0-9]*\/\([0-9]*\) decaps.*/\1/p')
      if [ -z "$OK" ] || grep -q "Process terminating" "$bin.vg"; then
        MOTIVO=$(grep -m1 -o "signal [0-9]* ([A-Z]*)" "$bin.vg")
        echo "$FECHA,pqclean,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_pqclean,$ITERS,,,,,,\"error de ejecución ${MOTIVO};$NOTA\"" >> "$CSV"
        echo "ML-KEM-$lvl $cc [$opt] -> ERROR DE EJECUCIÓN ${MOTIVO} (ver $bin.vg)"
        continue
      fi
      REP=$(grep -c 'Conditional jump\|Use of uninit' "$bin.vg")
      LOCS=$(grep -A1 'Conditional jump\|Use of uninit' "$bin.vg" | grep ' at ' | sed 's/.*: //' | sort -u)
      N=$(printf '%s' "$LOCS" | grep -c .)
      DET=$(printf '%s' "$LOCS" | tr '\n' ';' | sed 's/;$//')

      echo "$FECHA,pqclean,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_pqclean,$ITERS,$OK,$TOT,$REP,$N,\"$DET\",\"$NOTA\"" >> "$CSV"
      echo "ML-KEM-$lvl $cc [$opt] -> decaps $OK/$TOT | reportes $REP | ubicaciones con fuga: $N ${DET:+-> $DET}"
    done
  done
done
[ -n "${TMP:-}" ] && rm -rf "$TMP"
echo "Listo. Resultados agregados a $CSV"
