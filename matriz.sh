#!/usr/bin/env bash
# Corre la matriz de compiladores x flags sobre pq-crystals/kyber (ref/) y agrega
# una fila por configuración a resultados.csv.
#
# Uso:   ./matriz.sh <rol> <commit|rama> "<niveles K>" "<compiladores>" [iteraciones]
# Rol:   auditoria | control_positivo | control_negativo
# Ej.:   ./matriz.sh auditoria standard "2 3 4" "clang-18 clang-22 gcc-14"
#        ./matriz.sh control_positivo b628ba7 "2" "clang-20" 10
# Flags personalizados (separados por ;) con la variable FLAGS:
#        FLAGS="-O2 -flto;-Os -march=native;-Oz" ./matriz.sh auditoria standard "2" "clang-18"

set -u
if [ $# -lt 4 ]; then
  sed -n '2,11p' "$0"; exit 1
fi
ROL=$1; REF=$2; KS=$3; CCS=$4; ITERS=${5:-10}
ROOT=${CT_ROOT:-$HOME/ct-audit}
CSV=$ROOT/resultados.csv
HARNESS=$ROOT/harness_v2.c
SRC="kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c fips202.c symmetric-shake.c randombytes.c"

cd "$ROOT/kyber" && git checkout -q "$REF" || { echo "No pude hacer checkout de $REF"; exit 1; }
COMMIT=$(git rev-parse --short HEAD)
cd ref

if [ ! -f "$CSV" ]; then
  echo "fecha,libreria,commit,rol,operacion,kyber_k,compilador,version_compilador,flags,harness,iteraciones,decaps_ok,decaps_total,reportes_valgrind,ubicaciones_fuga,detalle_ubicaciones,notas" > "$CSV"
fi

FECHA=$(date -I)
for k in $KS; do
  for cc in $CCS; do
    if ! command -v "$cc" >/dev/null; then echo "Saltando $cc (no instalado)"; continue; fi
    VER=$("$cc" --version 2>/dev/null | head -1)
    # GCC y Clang usan flags distintos para desactivar la vectorización
    case $cc in gcc*) NOVEC="-O2 -fno-tree-vectorize" ;; *) NOVEC="-O2 -fno-vectorize" ;; esac

    if [ -n "${FLAGS:-}" ]; then
      IFS=';' read -r -a OPTS <<< "$FLAGS"
    else
      OPTS=("-O0" "-O1" "-O2" "-O3" "-Os" "$NOVEC")
    fi
    for opt in "${OPTS[@]}"; do
      bin=/tmp/m_${COMMIT}_${k}_${cc}_$(echo "$opt" | tr -d ' -' | tr '=' '_')

      if ! $cc $opt -g -DKYBER_K=$k -I. "$HARNESS" $SRC -o "$bin" 2>/tmp/cc.err; then
        echo "$FECHA,pq-crystals-ref,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_v2,$ITERS,,,,,,\"error de compilación\"" >> "$CSV"
        echo "K=$k $cc [$opt] -> ERROR DE COMPILACIÓN (ver /tmp/cc.err)"
        continue
      fi

      OUT=$(valgrind -q "$bin" "$ITERS" 2>"$bin.vg")
      OK=$(echo "$OUT"  | sed -n 's/.*: \([0-9]*\)\/[0-9]* decaps.*/\1/p')
      TOT=$(echo "$OUT" | sed -n 's/.*: [0-9]*\/\([0-9]*\) decaps.*/\1/p')

      # Si el programa no terminó bien (p. ej. SIGILL por instrucciones que Valgrind no soporta),
      # NO es un resultado limpio: se registra como error y se pasa a la siguiente configuración.
      if [ -z "$OK" ] || grep -q "Process terminating" "$bin.vg"; then
        MOTIVO=$(grep -m1 -o "signal [0-9]* ([A-Z]*)" "$bin.vg")
        echo "$FECHA,pq-crystals-ref,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_v2,$ITERS,,,,,,\"error de ejecución ${MOTIVO}\"" >> "$CSV"
        echo "K=$k $cc [$opt] -> ERROR DE EJECUCIÓN ${MOTIVO} (ver $bin.vg)"
        continue
      fi
      REP=$(grep -c 'Conditional jump\|Use of uninit' "$bin.vg")
      LOCS=$(grep -A1 'Conditional jump\|Use of uninit' "$bin.vg" | grep ' at ' | sed 's/.*: //' | sort -u)
      N=$(printf '%s' "$LOCS" | grep -c .)
      DET=$(printf '%s' "$LOCS" | tr '\n' ';' | sed 's/;$//')

      echo "$FECHA,pq-crystals-ref,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_v2,$ITERS,$OK,$TOT,$REP,$N,\"$DET\"," >> "$CSV"
      echo "K=$k $cc [$opt] -> decaps $OK/$TOT | reportes $REP | ubicaciones con fuga: $N ${DET:+-> $DET}"
    done
  done
done
echo "Listo. Resultados agregados a $CSV"
