"""Fuel custody, metering reconciliation and power-reserve settlement.

This module replaces the provisional ``fuel_reserve`` shortcut.  A driver's
signature records that fuel moved; it does not prove how much arrived, that the
fuel is usable, or that the site can keep an outage promise.  Every physical
delivery therefore carries its own metering original:

* vehicle meter reading and the temperature at which it was read,
* the meter's nominal (uncalibrated) correction factor,
* tank gauge before and after, with temperatures,
* generator test burn and its test duration,
* tank-bottom water and unextractable heel,
* custody seals and the observer.

Volumes at different temperatures are never added directly.  All inventory
comparisons are made on the contract temperature basis; gauge and bottom
volumes are converted before use.

Anything that is not verified usable (unverified oil quality, free water, or an
unextractable heel) is excluded from the hours a site may promise.  A later
meter calibration never shrinks the physical tank: it re-opens what the
supplier may bill and how wide the leak range is.

Settlement keeps four ledgers apart:

``supplier``    what the carrier ticket can support and what may be paid,
``environment`` what soil/water sampling says was released,
``transfer``    fuel and money moved between sites under seal,
``commitment``  hours actually promised to customers.

A later probe calibration re-runs the supplier and leak arithmetic without
rewriting the original delivery row, so both the provisional and the
calibrated figures remain auditable.
"""
from decimal import Decimal, ROUND_HALF_UP
from contextlib import contextmanager
import sqlite3

from .store import one, rows, tx

sqlite3.register_adapter(Decimal, float)

# --- metrology policy -------------------------------------------------------

CONTRACT_TEMP_C = Decimal('15')
CONTRACT_EXPANSION_PER_C = Decimal('0.00095')
GAUGE_TOLERANCE_FRACTION = Decimal('0.005')
SOIL_ESTIMATE_TOLERANCE_L = Decimal('0.05')
SOIL_DISPOSAL_RATE = Decimal('0.42')       # currency per kg of soil
WATER_DISPOSAL_RATE = Decimal('0.15')      # currency per litre of water
DEFAULT_UNIT_PRICE = Decimal('1.85')
DEFAULT_TRANSFER_PRICE = Decimal('2.05')

# Roles that may decide how much fuel to buy or move.  A driver and the site
# fuel custodian may record facts but never authorise a replenishment quantity.
SUPPLY_ROLES = {'incident_commander', 'neighbor_authority', 'quality_lead'}
COMMIT_ROLES = {'incident_commander', 'fuel_custodian'}
REVISE_ROLES = {'incident_commander', 'quality_lead'}

SCHEMA = """
CREATE TABLE IF NOT EXISTS fuel_tanks(
 id TEXT PRIMARY KEY, capacity_l REAL, gauge_l REAL, gauge_temp_c REAL,
 temperature_profile TEXT, water_l REAL DEFAULT 0,
 unextractable_l REAL DEFAULT 0, water_limit_l REAL DEFAULT 3.0,
 minimum_l REAL DEFAULT 270, minimum_hours REAL,
 generator_burn_l_per_h REAL);
CREATE TABLE IF NOT EXISTS fuel_meters(
 id TEXT PRIMARY KEY, site TEXT, nominal_factor REAL,
 probe_profile TEXT, calibration_id TEXT, calibration_factor REAL,
 calibration_signed INTEGER DEFAULT 0, calibration_at REAL);
CREATE TABLE IF NOT EXISTS fuel_deliveries(
 id TEXT PRIMARY KEY, tank_id TEXT, meter_id TEXT, vehicle_l REAL,
 vehicle_temp_c REAL, nominal_factor REAL, provisional_l REAL, driver TEXT,
 seal_id TEXT, seal_confirmed INTEGER, supplier TEXT, unit_price REAL);
CREATE TABLE IF NOT EXISTS fuel_samples(
 id TEXT PRIMARY KEY, tank_id TEXT, kind TEXT, water_l REAL, water_ppm REAL,
 soil_mass_kg REAL, tph_mg_per_kg REAL, density_kg_per_l REAL,
 laboratory TEXT, sealed INTEGER, quality TEXT, release_l REAL, at REAL);
CREATE TABLE IF NOT EXISTS fuel_settlements(
 id TEXT PRIMARY KEY, tank_id TEXT, delivery_id TEXT,
 before_l REAL, before_temp_c REAL, after_l REAL, after_temp_c REAL,
 before_contract_l REAL, after_contract_l REAL, delivered_contract_l REAL,
 generator_test_l REAL, generator_test_temp_c REAL, generator_test_hours REAL,
 generator_test_contract_l REAL, density_kg_per_l REAL, water_l REAL,
 unextractable_l REAL, observed_fuel_l REAL, expected_fuel_l REAL,
 unexplained_l REAL, seal_id TEXT, observed_by TEXT, status TEXT, at REAL);
CREATE TABLE IF NOT EXISTS fuel_transfers(
 id TEXT PRIMARY KEY, from_tank TEXT, to_tank TEXT, liters REAL,
 seal_id TEXT, quality_cleared INTEGER, cost REAL, at REAL);
CREATE TABLE IF NOT EXISTS fuel_actions(
 id TEXT PRIMARY KEY, tank_id TEXT, option TEXT, quantity_l REAL,
 approvals TEXT, quality_cleared INTEGER, from_tank TEXT,
 site_hours_now REAL, site_hours_after REAL, neighbor_hours_after REAL,
 supplier_payable REAL, transfer_cost REAL, at REAL);
CREATE TABLE IF NOT EXISTS fuel_commitments(
 id TEXT PRIMARY KEY, tank_id TEXT, hours REAL, usable_l REAL,
 burn_l_per_h REAL, minimum_hours REAL, additional_l REAL, status TEXT, at REAL);
"""


# --- numeric helpers --------------------------------------------------------

def _d(value):
    return Decimal(str(value))


def _q(value):
    return _d(value).quantize(Decimal('0.001'), rounding=ROUND_HALF_UP)


def _f(value):
    return float(_q(value))


def _money(value):
    return float(_d(value).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))


def _vcf(temp_c):
    """Volume correction factor to the contract temperature basis."""
    return Decimal(1) - CONTRACT_EXPANSION_PER_C * (_d(temp_c) - CONTRACT_TEMP_C)


def _contract(liters, temp_c):
    return _d(liters) * _vcf(temp_c)


@contextmanager
def _atomic(db):
    if db.in_transaction:
        yield
    else:
        with tx(db):
            yield


def _ensure(db):
    db.executescript(SCHEMA)


def _tank(db, tank_id):
    return one(db, 'SELECT * FROM fuel_tanks WHERE id=?', (tank_id,))


def _meter(db, meter_id):
    return one(db, 'SELECT * FROM fuel_meters WHERE id=?', (meter_id,))


def _delivery_contract(db, delivery):
    """Return (provisional, calibrated-or-None) contract litres for a delivery."""
    provisional = _d(delivery['provisional_l'])
    meter = _meter(db, delivery['meter_id'])
    if meter and meter['calibration_signed']:
        calibrated = _contract(delivery['vehicle_l'], delivery['vehicle_temp_c']) * _d(meter['calibration_factor'])
        return provisional, calibrated
    return provisional, None


def _latest_settlement(db, tank_id):
    return one(db, 'SELECT * FROM fuel_settlements WHERE tank_id=? ORDER BY rowid DESC LIMIT 1', (tank_id,))


def _latest_sample(db, tank_id, kind):
    return one(db, 'SELECT * FROM fuel_samples WHERE tank_id=? AND kind=? ORDER BY rowid DESC LIMIT 1',
               (tank_id, kind))


def _burn_rate(db, tank_id):
    settlement = _latest_settlement(db, tank_id)
    if settlement and settlement['generator_test_hours'] and settlement['generator_test_hours'] > 0:
        tested = _d(settlement['generator_test_contract_l'])
        if tested > 0:
            return tested / _d(settlement['generator_test_hours'])
    return None


def _reserve_raw(db, tank_id, minimum_l, minimum_hours=None, generator_burn_l_per_h=None):
    """Compute the reserve on the contract basis.  Internal Decimal result.

    The gauge is physical truth.  A meter calibration does not shrink the tank;
    it changes what the supplier may bill and how the leak range is read, so
    the two are deliberately not mixed here.
    """
    tank = _tank(db, tank_id)
    if not tank:
        return {'decision': 'unknown_tank'}

    gauge = _d(tank['gauge_l'])
    water = _d(tank['water_l'])
    heel = _d(tank['unextractable_l'])
    temp = _d(tank['gauge_temp_c'])

    physical = max(Decimal(0), gauge - water - heel) * _vcf(temp)
    usable = physical

    sample = _latest_sample(db, tank_id, 'tank_bottom')
    settlement = _latest_settlement(db, tank_id)
    if sample and settlement and _d(sample['at']) < _d(settlement['at']):
        # a quality clearance from before the latest delivery cannot vouch for
        # the fuel that delivery added
        quality = 'stale'
    else:
        quality = sample['quality'] if sample else 'unverified'
    quality_ok = quality == 'pass'

    burn = _d(generator_burn_l_per_h) if generator_burn_l_per_h is not None else _burn_rate(db, tank_id)
    if burn is None and tank['generator_burn_l_per_h']:
        burn = _d(tank['generator_burn_l_per_h'])
    minimum_l = _d(minimum_l)
    if minimum_hours is not None:
        minimum_hours = _d(minimum_hours)
    elif tank['minimum_hours'] is not None:
        minimum_hours = _d(tank['minimum_hours'])
    elif burn:
        minimum_hours = minimum_l / burn
    else:
        minimum_hours = None

    reasons = []
    if not quality_ok:
        reasons.append('quality_' + quality)
    if burn is None or burn <= 0:
        reasons.append('burn_rate_unknown')
        hours = Decimal(0)
    else:
        hours = usable / burn
    if minimum_hours is None:
        reasons.append('minimum_hours_unknown')

    ready = bool(
        quality_ok
        and burn is not None and burn > 0
        and minimum_hours is not None
        and usable >= minimum_l
        and hours >= minimum_hours
    )
    if usable < minimum_l:
        reasons.append('below_minimum_litres')
    if minimum_hours is not None and hours < minimum_hours:
        reasons.append('below_minimum_hours')

    return {
        'decision': 'ready' if ready else 'short',
        'tank_id': tank_id,
        'gauge_l': gauge,
        'water_l': water,
        'unextractable_l': heel,
        'gauge_temp_c': temp,
        'physical_usable_l': physical,
        'usable_l': usable,
        'quality': quality,
        'quality_ok': quality_ok,
        'burn_l_per_h': burn,
        'minimum_l': minimum_l,
        'minimum_hours': minimum_hours,
        'hours': hours,
        'deficit_l': max(Decimal(0), minimum_l - usable),
        'deficit_hours': max(Decimal(0), (minimum_hours or Decimal(0)) - hours),
        'ready': ready,
        'reasons': reasons,
    }


def _public_reserve(raw):
    if raw.get('decision') == 'unknown_tank':
        return raw
    out = dict(raw)
    for key in ('gauge_l', 'water_l', 'unextractable_l', 'gauge_temp_c', 'physical_usable_l',
                'usable_l', 'burn_l_per_h', 'minimum_l', 'minimum_hours',
                'hours', 'deficit_l', 'deficit_hours'):
        if out.get(key) is not None:
            out[key] = _f(out[key])
    return out


# --- tank and meter registration -------------------------------------------

def open_tank(db, *, tank_id, capacity_l, gauge_l, gauge_temp_c,
              temperature_profile='contract', water_l=0, unextractable_l=0,
              water_limit_l=3.0, minimum_l=270, minimum_hours=None,
              generator_burn_l_per_h=None):
    """Register a tank with its own promise and measured burn (if known)."""
    _ensure(db)
    with _atomic(db):
        old = _tank(db, tank_id)
        if old:
            return {'decision': 'reused', 'tank_id': tank_id}
        if capacity_l <= 0 or gauge_l < 0 or gauge_l > capacity_l or water_l < 0 or unextractable_l < 0:
            return {'decision': 'invalid_tank'}
        db.execute('INSERT INTO fuel_tanks VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   (tank_id, float(_d(capacity_l)), float(_d(gauge_l)),
                    float(_d(gauge_temp_c)), temperature_profile, float(_d(water_l)),
                    float(_d(unextractable_l)), float(_d(water_limit_l)),
                    float(_d(minimum_l)),
                    None if minimum_hours is None else float(_d(minimum_hours)),
                    None if generator_burn_l_per_h is None else float(_d(generator_burn_l_per_h))))
        return {'decision': 'opened', 'tank_id': tank_id, 'gauge_l': gauge_l}


def register_meter(db, *, meter_id, site, nominal_factor=Decimal('1'),
                   probe_profile='unverified'):
    _ensure(db)
    with _atomic(db):
        old = _meter(db, meter_id)
        if old:
            return {'decision': 'reused', 'meter_id': meter_id}
        if not _d(nominal_factor) > 0:
            return {'decision': 'invalid_meter'}
        db.execute('INSERT INTO fuel_meters VALUES(?,?,?,?,?,?,?,?)',
                   (meter_id, site, float(_d(nominal_factor)), probe_profile, None, None, 0, None))
        return {'decision': 'registered', 'meter_id': meter_id,
                'calibration_signed': False}


# --- delivery and measurement ----------------------------------------------

def delivery(db, *, delivery_id, tank_id, meter_id, vehicle_l, vehicle_temp_c,
             driver, seal_id, seal_confirmed, supplier, unit_price=DEFAULT_UNIT_PRICE):
    """Record a physical delivery.  Signature + seal are custody facts only."""
    _ensure(db)
    with _atomic(db):
        if one(db, 'SELECT id FROM fuel_deliveries WHERE id=?', (delivery_id,)):
            return {'decision': 'reused', 'delivery_id': delivery_id}
        tank = _tank(db, tank_id)
        meter = _meter(db, meter_id)
        if not tank or not meter:
            return {'decision': 'unavailable'}
        if not _d(vehicle_l) >= 0 or not _d(unit_price) >= 0:
            return {'decision': 'invalid_quantity'}
        if not driver or not str(driver).strip():
            return {'decision': 'driver_signature_missing'}
        if not seal_id or not str(seal_id).strip() or not seal_confirmed:
            return {'decision': 'seal_unconfirmed'}
        provisional = _contract(vehicle_l, vehicle_temp_c) * _d(meter['nominal_factor'])
        db.execute('INSERT INTO fuel_deliveries VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                   (delivery_id, tank_id, meter_id, float(_d(vehicle_l)),
                    float(_d(vehicle_temp_c)), float(_d(meter['nominal_factor'])),
                    float(_q(provisional)), driver, seal_id,
                    int(bool(seal_confirmed)), supplier, float(_d(unit_price))))
        return {'decision': 'recorded', 'delivery_id': delivery_id,
                'vehicle_l': _f(vehicle_l), 'vehicle_temp_c': _f(vehicle_temp_c),
                'provisional_l': _f(provisional),
                'thermal_correction_l': _f(_d(vehicle_l) - _contract(vehicle_l, vehicle_temp_c)),
                'seal_id': seal_id, 'driver': driver,
                'note': 'driver signature records custody, not delivered quantity'}


def sample(db, *, sample_id, tank_id, kind='tank_bottom', water_l=0, water_ppm=0,
           soil_mass_kg=None, tph_mg_per_kg=None, density_kg_per_l=Decimal('0.835'),
           laboratory=None, sealed=True, at=0):
    """Record a tank-bottom or soil sample.

    Tank-bottom water is an unusable volume; water above the tank's limit fails
    quality entirely.  A soil sample converts TPH mass to an estimated fuel
    release in litres so that environment and supplier ledgers stay separate.
    """
    _ensure(db)
    with _atomic(db):
        if one(db, 'SELECT id FROM fuel_samples WHERE id=?', (sample_id,)):
            return {'decision': 'reused', 'sample_id': sample_id}
        tank = _tank(db, tank_id)
        if not tank:
            return {'decision': 'unknown_tank'}
        if not sealed or not laboratory:
            return {'decision': 'sample_unsealed'}
        release = None
        quality = None
        if kind == 'tank_bottom':
            water = max(Decimal(0), _d(water_l))
            quality = 'pass' if (water <= _d(tank['water_limit_l']) and _d(water_ppm) <= 500) else 'fail'
            db.execute('UPDATE fuel_tanks SET water_l=? WHERE id=?', (float(water), tank_id))
        elif kind == 'soil':
            if soil_mass_kg is None or tph_mg_per_kg is None or not _d(density_kg_per_l) > 0:
                return {'decision': 'invalid_soil_sample'}
            release = _d(soil_mass_kg) * _d(tph_mg_per_kg) / Decimal(10 ** 6) / _d(density_kg_per_l)
            quality = 'contaminated' if release > 0 else 'clean'
        else:
            return {'decision': 'invalid_sample_kind'}
        db.execute('INSERT INTO fuel_samples VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (sample_id, tank_id, kind, water_l, water_ppm, soil_mass_kg,
                    tph_mg_per_kg, density_kg_per_l, laboratory, int(bool(sealed)),
                    quality, float(release) if release is not None else None, at))
        return {'decision': 'sampled', 'kind': kind, 'quality': quality,
                'release_l': _f(release) if release is not None else None,
                'laboratory': laboratory}


def settle(db, *, settlement_id, tank_id, delivery_id, before_l, before_temp_c,
           after_l, after_temp_c, density_kg_per_l, generator_test_l=0,
           generator_test_temp_c=None, generator_test_hours=0, water_l=None,
           unextractable_l=None, seal_id, observed_by, at=0):
    """Reconcile one delivery against gauge, burn and custody facts.

    ``observed_fuel_l`` is the gauge after the delivery minus free water.  The
    unextractable heel stays in the physical balance (it is fuel still in the
    tank) but is removed later by the reserve calculation, because it cannot be
    burned.  Mixing those two questions is what produced the original 20 L
    overstatement.
    """
    _ensure(db)
    with _atomic(db):
        if one(db, 'SELECT id FROM fuel_settlements WHERE id=?', (settlement_id,)):
            return {'decision': 'reused', 'settlement_id': settlement_id}
        tank = _tank(db, tank_id)
        delivery_row = one(db, 'SELECT * FROM fuel_deliveries WHERE id=? AND tank_id=?',
                           (delivery_id, tank_id))
        if not tank or not delivery_row:
            return {'decision': 'unavailable'}
        if not seal_id or seal_id != delivery_row['seal_id'] or not observed_by:
            return {'decision': 'custody_unconfirmed'}
        if abs(_d(tank['gauge_l']) - _d(before_l)) > Decimal('0.001'):
            return {'decision': 'gauge_state_mismatch',
                    'expected_before_l': _f(tank['gauge_l'])}
        if _d(after_l) < 0 or _d(before_l) < 0 or not _d(generator_test_hours) >= 0:
            return {'decision': 'invalid_measurement'}

        before_contract = _contract(before_l, before_temp_c)
        after_contract = _contract(after_l, after_temp_c)
        provisional, calibrated = _delivery_contract(db, delivery_row)
        delivered = calibrated if calibrated is not None else provisional

        test_temp = after_temp_c if generator_test_temp_c is None else generator_test_temp_c
        test_contract = _contract(generator_test_l, test_temp)
        expected = before_contract + delivered - test_contract

        water = _d(tank['water_l']) if water_l is None else max(Decimal(0), _d(water_l))
        heel = _d(tank['unextractable_l']) if unextractable_l is None else max(Decimal(0), _d(unextractable_l))
        observed_fuel = max(Decimal(0), _d(after_l) - water) * _vcf(after_temp_c)
        unexplained = expected - observed_fuel
        tolerance = GAUGE_TOLERANCE_FRACTION * _d(after_l)

        status = 'final' if calibrated is not None else 'pending_calibration'
        db.execute('INSERT INTO fuel_settlements VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (settlement_id, tank_id, delivery_id, before_l, before_temp_c,
                    after_l, after_temp_c, float(before_contract), float(after_contract),
                    float(delivered), generator_test_l, test_temp, generator_test_hours,
                    float(test_contract), density_kg_per_l, float(water), float(heel),
                    float(observed_fuel), float(expected), float(unexplained),
                    seal_id, observed_by, status, at))
        db.execute('UPDATE fuel_tanks SET gauge_l=?, gauge_temp_c=?, water_l=?, unextractable_l=? WHERE id=?',
                   (after_l, after_temp_c, float(water), float(heel), tank_id))
        return {
            'decision': 'reconciled',
            'settlement_id': settlement_id,
            'status': status,
            'before_contract_l': _f(before_contract),
            'after_contract_l': _f(after_contract),
            'delivered_contract_l': _f(delivered),
            'generator_test_contract_l': _f(test_contract),
            'observed_fuel_l': _f(observed_fuel),
            'expected_fuel_l': _f(expected),
            'unexplained_l': _f(unexplained),
            'naive_ticket_sum_l': _f(_d(before_l) + _d(delivery_row['vehicle_l']) - _d(generator_test_l)),
            'gauge_tolerance_l': _f(tolerance),
            'leak_suspected': unexplained > tolerance,
            'water_l': _f(water),
            'unextractable_l': _f(heel),
        }


# --- calibration ------------------------------------------------------------

def calibrate(db, *, meter_id, calibration_id, factor, signed_by, at=0):
    """Sign a meter calibration and re-open the provisional arithmetic.

    The original delivery row is never edited.  The signed factor revises the
    supplier payable and the leak range; it does not rewrite the physical tank
    gauge, because the gauge already measured what actually arrived.
    """
    _ensure(db)
    with _atomic(db):
        meter = _meter(db, meter_id)
        if not meter:
            return {'decision': 'unknown_meter'}
        if not signed_by or not str(signed_by).strip():
            return {'decision': 'calibration_unsigned'}
        if not _d(factor) > 0:
            return {'decision': 'invalid_factor'}
        if meter['calibration_signed']:
            return {'decision': 'reused', 'meter_id': meter_id,
                    'factor': meter['calibration_factor'],
                    'calibration_id': meter['calibration_id']}
        db.execute('UPDATE fuel_meters SET calibration_id=?, calibration_factor=?, calibration_signed=1, calibration_at=? WHERE id=?',
                   (calibration_id, float(factor), at, meter_id))
        affected = []
        delta_l = Decimal(0)
        delta_amount = Decimal(0)
        for row in rows(db, 'SELECT * FROM fuel_deliveries WHERE meter_id=?', (meter_id,)):
            provisional = _d(row['provisional_l'])
            calibrated = _contract(row['vehicle_l'], row['vehicle_temp_c']) * _d(factor)
            delta = provisional - calibrated
            delta_l += delta
            delta_amount += delta * _d(row['unit_price'])
            affected.append({'delivery_id': row['id'],
                             'provisional_l': _f(provisional),
                             'calibrated_l': _f(calibrated),
                             'delta_l': _f(delta),
                             'delta_amount': _money(delta * _d(row['unit_price']))})
        return {
            'decision': 'calibrated',
            'meter_id': meter_id,
            'calibration_id': calibration_id,
            'factor': _f(factor),
            'signed_by': signed_by,
            'affected_deliveries': affected,
            'supplier_delta_l': _f(delta_l),
            'supplier_delta_amount': _money(delta_amount),
            'note': ('supplier payable and leak range are recomputed; '
                     'the original delivery row and tank gauge are unchanged'),
        }


# --- reserve, settlement report --------------------------------------------

def reserve(db, *, tank_id, minimum_l=None, minimum_hours=None,
            generator_burn_l_per_h=None):
    """Public reserve check; defaults to the tank's own contracted minimum."""
    _ensure(db)
    tank = _tank(db, tank_id)
    if not tank:
        return {'decision': 'unknown_tank'}
    if minimum_l is None:
        minimum_l = tank['minimum_l']
    return _public_reserve(_reserve_raw(db, tank_id, minimum_l, minimum_hours,
                                       generator_burn_l_per_h))


def report(db, *, tank_id):
    """Full audit view joining metering, supplier, environment and reserve."""
    _ensure(db)
    tank = _tank(db, tank_id)
    if not tank:
        return {'decision': 'unknown_tank'}
    settlement = _latest_settlement(db, tank_id)
    delivery_row = one(db, 'SELECT * FROM fuel_deliveries WHERE id=?',
                       (settlement['delivery_id'],)) if settlement else None
    meter = _meter(db, delivery_row['meter_id']) if delivery_row else None

    metering = None
    supplier = None
    if delivery_row:
        provisional, calibrated = _delivery_contract(db, delivery_row)
        vehicle_contract = _contract(delivery_row['vehicle_l'], delivery_row['vehicle_temp_c'])
        price = _d(delivery_row['unit_price'])
        ticket_full_amount = _d(delivery_row['vehicle_l']) * price
        provisional_amount = provisional * price
        calibrated_amount = calibrated * price if calibrated is not None else None
        metering = {
            'delivery_id': delivery_row['id'],
            'vehicle_meter_id': delivery_row['meter_id'],
            'vehicle_l': _f(delivery_row['vehicle_l']),
            'vehicle_temp_c': _f(delivery_row['vehicle_temp_c']),
            'contract_thermal_l': _f(vehicle_contract),
            'nominal_factor': _f(delivery_row['nominal_factor']),
            'provisional_contract_l': _f(provisional),
            'calibrated_contract_l': _f(calibrated) if calibrated is not None else None,
            'calibration_signed': bool(meter and meter['calibration_signed']),
            'meter_correction_l': _f(vehicle_contract - provisional),
        }
        supplier = {
            'ticket_full_l': _f(delivery_row['vehicle_l']),
            'ticket_full_amount': _money(ticket_full_amount),
            'provisional_l': _f(provisional),
            'provisional_amount': _money(provisional_amount),
            'withheld_vs_ticket_l': _f(_d(delivery_row['vehicle_l']) - provisional),
            'withheld_vs_ticket_amount': _money(ticket_full_amount - provisional_amount),
            'calibrated_l': _f(calibrated) if calibrated is not None else None,
            'calibrated_amount': _money(calibrated_amount) if calibrated_amount is not None else None,
            'calibration_delta_l': _f(provisional - calibrated) if calibrated is not None else None,
            'calibration_delta_amount': _money((provisional - calibrated) * price) if calibrated is not None else None,
        }

    tank_view = {
        'gauge_l': _f(tank['gauge_l']),
        'gauge_temp_c': _f(tank['gauge_temp_c']),
        'water_l': _f(tank['water_l']),
        'unextractable_l': _f(tank['unextractable_l']),
    }

    settlement_view = None
    soil = _latest_sample(db, tank_id, 'soil')
    environment = None
    if settlement:
        _, calibrated = _delivery_contract(db, delivery_row)
        delayed = calibrated if calibrated is not None else _d(settlement['delivered_contract_l'])
        expected = _d(settlement['before_contract_l']) + delayed - _d(settlement['generator_test_contract_l'])
        unexplained = expected - _d(settlement['observed_fuel_l'])
        settlement_view = {
            'settlement_id': settlement['id'],
            'expected_fuel_l': _f(expected),
            'observed_fuel_l': _f(settlement['observed_fuel_l']),
            'unexplained_l': _f(unexplained),
            'naive_ticket_sum_l': _f(_d(settlement['before_l']) + _d(delivery_row['vehicle_l']) - _d(settlement['generator_test_l'])),
            'status': settlement['status'],
        }
        water = _d(tank['water_l'])
        if soil and soil['release_l'] is not None:
            soil_release = _d(soil['release_l'])
            low = max(Decimal(0), min(unexplained, soil_release))
            high = max(unexplained, soil_release) + GAUGE_TOLERANCE_FRACTION * _d(settlement['after_l']) + SOIL_ESTIMATE_TOLERANCE_L
            environment = {
                'soil_mass_kg': _f(soil['soil_mass_kg']),
                'tph_mg_per_kg': _f(soil['tph_mg_per_kg']),
                'soil_release_l': _f(soil_release),
                'tank_gap_l': _f(unexplained),
                'additional_release_l': _f(max(Decimal(0), soil_release - unexplained)),
                'release_low_l': _f(low),
                'release_high_l': _f(high),
                'disposal_soil_kg': _f(soil['soil_mass_kg']),
                'disposal_water_l': _f(water),
                'disposal_cost': _money(_d(soil['soil_mass_kg']) * SOIL_DISPOSAL_RATE + water * WATER_DISPOSAL_RATE),
            }
    return {
        'decision': 'reported',
        'tank_id': tank_id,
        'metering_original': metering,
        'supplier': supplier,
        'tank': tank_view,
        'settlement': settlement_view,
        'environment': environment,
        'reserve': _public_reserve(_reserve_raw(db, tank_id, tank['minimum_l'])),
    }


# --- replenishment authority ------------------------------------------------

def _approvals(approvals):
    pairs = []
    for item in approvals or []:
        if isinstance(item, dict):
            pairs.append((item.get('actor'), item.get('role')))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            pairs.append((item[0], item[1]))
        else:
            pairs.append((None, item))
    return pairs


def authorize_supply(db, *, action_id, tank_id, option, quantity_l, approvals,
                     at=0, neighbor_tank_id=None, quality_cleared=False,
                     seal_id=None):
    """Authorise one of the two contract-permitted replenishment actions.

    ``stop_and_reorder``         stop the standby promise, buy verified fuel
                                 from the supplier; the neighbour is untouched.
    ``sealed_transfer``          move tested fuel from a neighbour in a sealed
                                 portable tank; the neighbour's own minimum
                                 reserve must still hold afterwards.

    The quantity decision belongs to the incident commander (plus the
    neighbour's authority and quality lead for a cross-site transfer).  A
    driver or the fuel custodian may never set it.  While the probe
    calibration is unsigned, the reorder is capped by the measured usable
    deficit, not by the carrier's 200 litre ticket.
    """
    _ensure(db)
    with _atomic(db):
        if one(db, 'SELECT id FROM fuel_actions WHERE id=?', (action_id,)):
            return {'decision': 'reused', 'action_id': action_id}
        site = _reserve_raw(db, tank_id, _tank(db, tank_id)['minimum_l'])
        deficit = site['deficit_l']
        if site['burn_l_per_h'] is None or site['burn_l_per_h'] <= 0:
            return {'decision': 'burn_rate_unknown',
                    'reason': 'cannot convert litres to promised hours'}
        pairs = _approvals(approvals)
        roles = {role for _, role in pairs}
        actors = [actor for actor, _ in pairs if actor]
        if not pairs or any(role not in SUPPLY_ROLES for _, role in pairs):
            return {'decision': 'unauthorized', 'reason': 'role_not_permitted'}

        if option == 'stop_and_reorder':
            if 'incident_commander' not in roles:
                return {'decision': 'unauthorized', 'reason': 'incident_commander_required'}
            if deficit <= 0:
                return {'decision': 'no_deficit'}
            quantity = _d(quantity_l)
            if quantity < deficit:
                return {'decision': 'insufficient_restoration', 'deficit_l': _f(deficit)}
            if quantity > deficit * Decimal('1.10'):
                return {'decision': 'quantity_unjustified',
                        'reason': 'unsigned_calibration_caps_quantity_to_measured_deficit',
                        'max_quantity_l': _f(deficit * Decimal('1.10'))}
            delivery_row = one(db, 'SELECT * FROM fuel_deliveries WHERE tank_id=? ORDER BY rowid DESC LIMIT 1',
                               (tank_id,))
            meter = _meter(db, delivery_row['meter_id']) if delivery_row else None
            price = _d(delivery_row['unit_price']) if delivery_row else DEFAULT_UNIT_PRICE
            provisional = _d(delivery_row['provisional_l']) if delivery_row else Decimal(0)
            supplier_payable = provisional * price + quantity * price
            burn = site['burn_l_per_h'] or Decimal(0)
            hours_after = (site['usable_l'] + quantity) / burn if burn > 0 else Decimal(0)
            db.execute('INSERT INTO fuel_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (action_id, tank_id, option, float(quantity),
                        str([(a, r) for a, r in pairs]), int(bool(quality_cleared)), None,
                        0.0, float(hours_after), None,
                        _money(supplier_payable), 0.0, at))
            return {
                'decision': 'authorized',
                'option': option,
                'fuel_source': 'supplier_reorder',
                'quantity_l': _f(quantity),
                'commitment_suspended': True,
                'hours_available_now': 0.0,
                'hours_after_resupply': _f(hours_after),
                'site_ready_after': hours_after >= (site['minimum_hours'] or Decimal(0)),
                'neighbor_hours_after': None,
                'supplier_payable_total': _money(supplier_payable),
                'transfer_cost': 0.0,
                'calibration_signed': bool(meter and meter['calibration_signed']),
                'quantity_authority': 'incident_commander_measured_deficit',
            }

        if option == 'sealed_transfer':
            if not {'incident_commander', 'neighbor_authority', 'quality_lead'} <= roles:
                return {'decision': 'unauthorized',
                        'reason': 'incident_commander_neighbor_authority_quality_lead_required'}
            if len(set(actors)) < 3:
                return {'decision': 'unauthorized', 'reason': 'separate_signatories_required'}
            if not quality_cleared:
                return {'decision': 'quality_unconfirmed', 'reason': 'transferred_fuel_not_tested'}
            if not seal_id or not str(seal_id).strip():
                return {'decision': 'seal_unconfirmed'}
            if not neighbor_tank_id:
                return {'decision': 'neighbor_required'}
            donor_min_l = _d(_tank(db, neighbor_tank_id)['minimum_l']) if _tank(db, neighbor_tank_id) else Decimal(0)
            donor = _reserve_raw(db, neighbor_tank_id, donor_min_l)
            if donor.get('decision') == 'unknown_tank' or not donor['quality_ok']:
                return {'decision': 'neighbor_unavailable'}
            amount = _d(quantity_l)
            if amount < deficit:
                return {'decision': 'insufficient_restoration', 'deficit_l': _f(deficit)}
            donor_surplus = donor['usable_l'] - donor_min_l
            if amount > donor_surplus:
                return {'decision': 'donor_reserve_breach',
                        'donor_surplus_l': _f(donor_surplus),
                        'note': 'the same batch cannot be ready at both sites'}
            donor_tank = _tank(db, neighbor_tank_id)
            receiver_tank = _tank(db, tank_id)
            donor_gauge = amount / _vcf(donor_tank['gauge_temp_c'])
            receiver_gauge = amount / _vcf(receiver_tank['gauge_temp_c'])
            db.execute('UPDATE fuel_tanks SET gauge_l=? WHERE id=?',
                       (float(_d(donor_tank['gauge_l']) - donor_gauge), neighbor_tank_id))
            db.execute('UPDATE fuel_tanks SET gauge_l=? WHERE id=?',
                       (float(_d(receiver_tank['gauge_l']) + receiver_gauge), tank_id))
            price = DEFAULT_TRANSFER_PRICE
            delivery_row = one(db, 'SELECT * FROM fuel_deliveries WHERE tank_id=? ORDER BY rowid DESC LIMIT 1',
                               (tank_id,))
            supplier_payable = _d(delivery_row['provisional_l']) * _d(delivery_row['unit_price']) if delivery_row else Decimal(0)
            transfer_cost = amount * price
            db.execute('INSERT INTO fuel_transfers VALUES(?,?,?,?,?,?,?,?)',
                       (action_id, neighbor_tank_id, tank_id, float(amount), seal_id,
                        int(bool(quality_cleared)), float(transfer_cost), at))
            after_site = _reserve_raw(db, tank_id, _tank(db, tank_id)['minimum_l'])
            after_donor = _reserve_raw(db, neighbor_tank_id, donor_min_l)
            if not after_donor['ready']:
                # undo: the donor must remain able to carry its own promise
                db.execute('UPDATE fuel_tanks SET gauge_l=? WHERE id=?',
                           (donor_tank['gauge_l'], neighbor_tank_id))
                db.execute('UPDATE fuel_tanks SET gauge_l=? WHERE id=?',
                           (receiver_tank['gauge_l'], tank_id))
                db.execute('DELETE FROM fuel_transfers WHERE id=?', (action_id,))
                return {'decision': 'donor_reserve_breach',
                        'donor_surplus_l': _f(donor_surplus),
                        'note': 'the same batch cannot be ready at both sites'}
            db.execute('INSERT INTO fuel_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (action_id, tank_id, option, float(amount),
                        str([(a, r) for a, r in pairs]), 1, neighbor_tank_id,
                        float(after_site['hours']), float(after_site['hours']),
                        float(after_donor['hours']), _money(supplier_payable),
                        _money(transfer_cost), at))
            return {
                'decision': 'authorized',
                'option': option,
                'fuel_source': 'neighbor_sealed_transfer',
                'quantity_l': _f(amount),
                'commitment_suspended': False,
                'hours_available_now': _f(after_site['hours']),
                'hours_after_resupply': _f(after_site['hours']),
                'site_ready_after': after_site['ready'],
                'neighbor_hours_after': _f(after_donor['hours']),
                'neighbor_ready_after': after_donor['ready'],
                'neighbor_minimum_l': _f(donor_min_l),
                'supplier_payable_total': _money(supplier_payable),
                'transfer_cost': _money(transfer_cost),
                'seal_id': seal_id,
                'quantity_authority': 'incident_commander_plus_neighbor_authority',
            }

        return {'decision': 'unknown_option'}


# --- customer commitment and later revision --------------------------------

def commit_hours(db, *, commitment_id, tank_id, minimum_hours, actor, role, at=0):
    """Promise only hours backed by certified usable fuel."""
    _ensure(db)
    with _atomic(db):
        if one(db, 'SELECT id FROM fuel_commitments WHERE id=?', (commitment_id,)):
            return {'decision': 'reused', 'commitment_id': commitment_id}
        if role not in COMMIT_ROLES or not actor:
            return {'decision': 'unauthorized', 'reason': 'role_not_permitted'}
        raw = _reserve_raw(db, tank_id, _tank(db, tank_id)['minimum_l'], minimum_hours=minimum_hours)
        if not raw['quality_ok']:
            return {'decision': 'not_committable', 'reason': 'quality_' + raw['quality']}
        if raw['burn_l_per_h'] is None or raw['burn_l_per_h'] <= 0:
            return {'decision': 'not_committable', 'reason': 'burn_rate_unknown'}
        decision = 'committed' if raw['hours'] >= _d(minimum_hours) else 'not_committable'
        db.execute('INSERT INTO fuel_commitments VALUES(?,?,?,?,?,?,?,?,?)',
                   (commitment_id, tank_id, float(raw['hours']), float(raw['usable_l']),
                    float(raw['burn_l_per_h']), float(minimum_hours), 0.0, decision, at))
        return {
            'decision': decision,
            'commitment_id': commitment_id,
            'hours': _f(raw['hours']),
            'usable_l': _f(raw['usable_l']),
            'burn_l_per_h': _f(raw['burn_l_per_h']),
            'minimum_hours': _f(minimum_hours),
            'fuel_source': 'tank_inventory',
        }


def revise_commitment(db, *, commitment_id, actor, role, soil_release_l=None, at=0):
    """Re-state already-promised hours after a confirmed soil release.

    The tank gap and the soil estimate are distinct numbers.  Only the part of
    the soil estimate that the tank reconciliation cannot explain reduces the
    usable fuel; the supplier shortfall is never treated as leak, and a leak is
    never used to pay the supplier's full ticket.
    """
    _ensure(db)
    with _atomic(db):
        commitment = one(db, 'SELECT * FROM fuel_commitments WHERE id=?', (commitment_id,))
        if not commitment:
            return {'decision': 'unknown_commitment'}
        if role not in REVISE_ROLES or not actor:
            return {'decision': 'unauthorized', 'reason': 'role_not_permitted'}
        tank_id = commitment['tank_id']
        settlement = _latest_settlement(db, tank_id)
        soil = _latest_sample(db, tank_id, 'soil')
        if soil_release_l is None:
            if not soil or soil['release_l'] is None:
                return {'decision': 'no_soil_evidence'}
            soil_release = _d(soil['release_l'])
        else:
            soil_release = _d(soil_release_l)
        if not settlement:
            return {'decision': 'no_settlement'}
        delivery_row = one(db, 'SELECT * FROM fuel_deliveries WHERE id=?', (settlement['delivery_id'],))
        _, calibrated = _delivery_contract(db, delivery_row)
        delivered = calibrated if calibrated is not None else _d(settlement['delivered_contract_l'])
        expected = _d(settlement['before_contract_l']) + delivered - _d(settlement['generator_test_contract_l'])
        tank_gap = expected - _d(settlement['observed_fuel_l'])
        tolerance = GAUGE_TOLERANCE_FRACTION * _d(settlement['after_l']) + SOIL_ESTIMATE_TOLERANCE_L
        additional = max(Decimal(0), soil_release - max(Decimal(0), tank_gap))

        raw = _reserve_raw(db, tank_id, _tank(db, tank_id)['minimum_l'])
        already_removed = sum(
            _d(row['additional_l']) for row in
            rows(db, 'SELECT additional_l FROM fuel_commitments WHERE tank_id=? AND id<>?',
                 (tank_id, commitment_id)))
        new_usable = max(Decimal(0), raw['usable_l'] - already_removed - additional)
        burn = raw['burn_l_per_h']
        if burn is None or burn <= 0:
            return {'decision': 'burn_rate_unknown'}
        new_hours = new_usable / burn
        declared = _d(commitment['hours'])
        retracted = max(Decimal(0), declared - new_hours)
        breached = new_hours < _d(commitment['minimum_hours'])
        status = 'revised' if retracted > 0 else 'unchanged'
        if breached:
            status = 'commitment_breached'
        db.execute('UPDATE fuel_commitments SET hours=?, usable_l=?, additional_l=?, status=? WHERE id=?',
                   (float(new_hours), float(new_usable), float(additional), status, commitment_id))
        low = max(Decimal(0), min(max(Decimal(0), tank_gap), soil_release))
        high = max(max(Decimal(0), tank_gap), soil_release) + tolerance
        return {
            'decision': status,
            'commitment_id': commitment_id,
            'hours_declared': _f(declared),
            'hours_supported': _f(new_hours),
            'hours_retracted': _f(retracted),
            'usable_l': _f(new_usable),
            'burn_l_per_h': _f(burn),
            'minimum_hours': _f(commitment['minimum_hours']),
            'commitment_breached': breached,
            'customer_notice_required': breached,
            'tank_gap_l': _f(tank_gap),
            'soil_release_l': _f(soil_release),
            'additional_release_l': _f(additional),
            'release_low_l': _f(low),
            'release_high_l': _f(high),
            'environment_disposal_kg': _f(_d(soil['soil_mass_kg'])) if soil and soil['soil_mass_kg'] is not None else None,
            'note': 'declared hours are bounded by certified usable fuel, not by the carrier ticket',
        }
