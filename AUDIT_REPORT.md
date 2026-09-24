# SafeStack Zero-Trust Saugumo Audito Ataskaita

- **Projektas:** `Safestack-Zero-Trust`
- **Projekto ID:** `project-014`
- **Viešasis raktas:** `riMRZ7qIs9V90nbjo61vB+qD/etrU/MYy6CnB7b1wMk=`
- **Rakto atspaudas:** `fbca5cce3c88dced96f0439414e91e524bfce550f29f4131db360aaf25f7373d`
- **Būsena:** **PATVIRTINTA (PASS)**
- **Versija:** v0.1.0
- **Data:** 2026-09-24

---

## 1. Tikrinimo Apimtis ir Metodika

Auditas atliktas pagal SafeStack Zero-Trust reikalavimus:
1. **Numatytojo draudimo (Default-Deny) taisyklė:** Bet kuri užklausa be aiškios leidžiančios taisyklės yra atmetama;
2. **Kriptografinis ryšulių pasirašymas:** Patvirtinti Ed25519 parašų generavimo ir patikros mechanizmai;
3. **Įrenginio būsenos (Device Posture) vartai:** Prieiga suteikiama tik registruotiems ir patvirtintiems įrenginiams;
4. **Vientisumo testai:** Visi šeši vieneto testai sėkmingai išlaikyti.

---

## 2. Testavimo Rezultatai

- `tests/test_zt.py`: PASS (Numatytasis atmetimas, taisyklių taikymas, įrenginių registracija, Ed25519 pasirašymas ir patikra).

Būsena: **OK**.
