"""Six acceptance trajectories for fuel custody and settlement.

1. thermal expansion            2. probe calibration failure
3. water in the tank bottom     4. generator test burn
5. soil leak                    6. neighbour sealed transfer

Scenario constants: 100 L on the gauge before arrival, a 200 L carrier ticket
read at 38 C, a 20 L generator test at 30 C, a 260 L gauge afterwards, a 2 L
free-water bottom layer, an 8 L unextractable heel, a signed factor of 0.946,
and a 270 L minimum for the site.
"""
import unittest

from edgehandoff.fuel_custody import (
    authorize_supply, calibrate, commit_hours, delivery, open_tank, register_meter,
    report, reserve, revise_commitment, sample, settle,
)
from edgehandoff.store import connect

APPROVERS = [
    {'actor': 'Commander', 'role': 'incident_commander'},
    {'actor': 'Neighbor Lead', 'role': 'neighbor_authority'},
    {'actor': 'Quality Lead', 'role': 'quality_lead'},
]


class FuelCustodyTest(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        open_tank(self.db, tank_id='T-SITE', capacity_l=1000, gauge_l=100,
                  gauge_temp_c=30)
        open_tank(self.db, tank_id='T-NEIGHBOR', capacity_l=1000, gauge_l=490,
                  gauge_temp_c=30)
        register_meter(self.db, meter_id='M-SITE', site='site')
        register_meter(self.db, meter_id='M-NEIGHBOR', site='neighbor')

    def tearDown(self):
        self.db.close()

    # helpers ---------------------------------------------------------------
    def record_delivery(self, delivery_id='D-1', meter_id='M-SITE',
                        tank_id='T-SITE', vehicle_l=200, vehicle_temp_c=38):
        return delivery(self.db, delivery_id=delivery_id, tank_id=tank_id,
                        meter_id=meter_id, vehicle_l=vehicle_l,
                        vehicle_temp_c=vehicle_temp_c, driver='A. Driver',
                        seal_id='SEAL-1', seal_confirmed=True, supplier='Fuel Co')

    def reconcile(self, settlement_id='S-1', tank_id='T-SITE', delivery_id='D-1',
                  before_l=100, after_l=260, water_l=2, heel_l=8,
                  generator_test_l=20, generator_test_hours=1.25,
                  seal_id='SEAL-1'):
        return settle(self.db, settlement_id=settlement_id, tank_id=tank_id,
                      delivery_id=delivery_id, before_l=before_l,
                      before_temp_c=30, after_l=after_l, after_temp_c=30,
                      density_kg_per_l=0.835, generator_test_l=generator_test_l,
                      generator_test_temp_c=30,
                      generator_test_hours=generator_test_hours,
                      water_l=water_l, unextractable_l=heel_l, seal_id=seal_id,
                      observed_by='Site custodian')

    def pass_quality(self, tank_id='T-SITE', sample_id='Q-1', water_l=2,
                     water_ppm=120):
        return sample(self.db, sample_id=sample_id, tank_id=tank_id,
                      kind='tank_bottom', water_l=water_l, water_ppm=water_ppm,
                      laboratory='Lab A', at=1)

    def authorize(self, action_id, option, quantity_l, approvals=APPROVERS,
                  **fields):
        return authorize_supply(self.db, action_id=action_id, tank_id='T-SITE',
                                option=option, quantity_l=quantity_l,
                                approvals=approvals, **fields)

    # 1. thermal expansion --------------------------------------------------
    def test_trajectory_thermal_expansion(self):
        """200 L read at 38 C is 195.630 L on the contract basis."""
        recorded = self.record_delivery()
        self.assertEqual(recorded['decision'], 'recorded')
        self.assertAlmostEqual(recorded['provisional_l'], 195.630, places=3)
        self.assertAlmostEqual(recorded['thermal_correction_l'], 4.370, places=3)

        reconciled = self.reconcile()
        self.assertEqual(reconciled['decision'], 'reconciled')
        self.assertEqual(reconciled['status'], 'pending_calibration')
        # 100 + 200 - 20 = 280 is not a volume on one basis
        self.assertAlmostEqual(reconciled['naive_ticket_sum_l'], 280.0, places=3)
        self.assertAlmostEqual(reconciled['expected_fuel_l'], 274.490, places=3)
        self.assertAlmostEqual(reconciled['observed_fuel_l'], 254.324, places=3)
        self.assertAlmostEqual(reconciled['unexplained_l'], 20.167, places=3)
        self.assertTrue(reconciled['leak_suspected'])

    # 2. probe calibration failure ------------------------------------------
    def test_trajectory_probe_miscalibration(self):
        """An unsigned probe means the 200 L ticket may not be paid or promised."""
        self.record_delivery()
        self.reconcile()
        self.pass_quality()

        provisional_report = report(self.db, tank_id='T-SITE')
        self.assertFalse(provisional_report['metering_original']['calibration_signed'])
        self.assertAlmostEqual(provisional_report['supplier']['provisional_l'], 195.630, places=3)
        self.assertAlmostEqual(provisional_report['supplier']['provisional_amount'], 361.92, places=2)
        self.assertAlmostEqual(provisional_report['supplier']['withheld_vs_ticket_l'], 4.370, places=3)
        self.assertAlmostEqual(provisional_report['supplier']['withheld_vs_ticket_amount'], 8.08, places=2)
        self.assertIsNone(provisional_report['supplier']['calibrated_l'])

        unsigned = calibrate(self.db, meter_id='M-SITE', calibration_id='CAL-0',
                             factor=0.946, signed_by='', at=2)
        self.assertEqual(unsigned['decision'], 'calibration_unsigned')

        signed = calibrate(self.db, meter_id='M-SITE', calibration_id='CAL-1',
                           factor=0.946, signed_by='Metrology Lab', at=2)
        self.assertEqual(signed['decision'], 'calibrated')
        self.assertAlmostEqual(signed['supplier_delta_l'], 10.564, places=3)
        self.assertAlmostEqual(signed['supplier_delta_amount'], 19.54, places=2)

        # the original delivery row is immutable; both views stay recomputable
        original = dict(self.db.execute(
            "SELECT * FROM fuel_deliveries WHERE id='D-1'").fetchone())
        self.assertAlmostEqual(original['provisional_l'], 195.630, places=3)
        final = report(self.db, tank_id='T-SITE')
        self.assertTrue(final['metering_original']['calibration_signed'])
        self.assertAlmostEqual(final['supplier']['calibrated_l'], 185.066, places=3)
        self.assertAlmostEqual(final['supplier']['calibrated_amount'], 342.37, places=2)
        self.assertAlmostEqual(final['supplier']['calibration_delta_amount'], 19.54, places=2)
        self.assertAlmostEqual(final['settlement']['unexplained_l'], 9.602, places=3)
        # with a soil sample, the calibrated range is narrower than the ticket's
        sample(self.db, sample_id='SOIL-1', tank_id='T-SITE', kind='soil',
               soil_mass_kg=1500, tph_mg_per_kg=4800, density_kg_per_l=0.835,
               laboratory='Lab A', at=2)
        final = report(self.db, tank_id='T-SITE')
        self.assertAlmostEqual(final['environment']['release_high_l'], 10.952, places=3)

        # the gauge did not change when the paper factor changed
        reserve_after = reserve(self.db, tank_id='T-SITE', minimum_l=270)
        self.assertEqual(reserve_after['decision'], 'short')
        self.assertAlmostEqual(reserve_after['usable_l'], 246.438, places=3)

    # 3. water in the tank bottom -------------------------------------------
    def test_trajectory_bottom_water_is_not_usable(self):
        """A 260 L stick reading is not 260 L of fuel; water and heel are removed."""
        self.record_delivery()
        self.reconcile()
        before = reserve(self.db, tank_id='T-SITE', minimum_l=270)
        self.assertEqual(before['decision'], 'short')
        self.assertEqual(before['quality'], 'unverified')
        self.assertFalse(before['quality_ok'])
        self.assertAlmostEqual(before['usable_l'], 246.438, places=3)
        self.assertAlmostEqual(before['burn_l_per_h'], 15.772, places=3)
        self.assertAlmostEqual(before['hours'], 15.625, places=3)

        failed = self.pass_quality(sample_id='Q-BAD', water_l=20)
        self.assertEqual(failed['quality'], 'fail')
        self.assertEqual(reserve(self.db, tank_id='T-SITE', minimum_l=270)['decision'], 'short')

        passed = self.pass_quality(sample_id='Q-OK', water_l=2)
        self.assertEqual(passed['quality'], 'pass')
        after = reserve(self.db, tank_id='T-SITE', minimum_l=270, minimum_hours=18)
        self.assertAlmostEqual(after['usable_l'], 246.438, places=3)
        self.assertAlmostEqual(after['hours'], 15.625, places=3)
        self.assertAlmostEqual(after['minimum_hours'], 18.0, places=3)
        self.assertEqual(after['decision'], 'short')
        self.assertIn('below_minimum_litres', after['reasons'])
        self.assertIn('below_minimum_hours', after['reasons'])
        self.assertLess(after['usable_l'], 270)

    # 4. generator test burn ------------------------------------------------
    def test_trajectory_generator_test_burn(self):
        """Hours come from tested burn and tested fuel, not from tank litres."""
        self.record_delivery()
        self.reconcile(generator_test_l=20, generator_test_hours=1.0)
        self.pass_quality()
        heavy = reserve(self.db, tank_id='T-SITE', minimum_l=270)
        self.assertAlmostEqual(heavy['burn_l_per_h'], 19.715, places=3)
        self.assertAlmostEqual(heavy['hours'], 12.5, places=3)

        # an identical tank whose test ran longer (lighter burn) lasts longer
        open_tank(self.db, tank_id='T-SITE-2', capacity_l=1000, gauge_l=100,
                  gauge_temp_c=30)
        self.record_delivery(delivery_id='D-2', tank_id='T-SITE-2')
        self.reconcile(settlement_id='S-2', tank_id='T-SITE-2', delivery_id='D-2',
                       generator_test_l=20, generator_test_hours=1.25)
        self.pass_quality(tank_id='T-SITE-2', sample_id='Q-2')
        light = reserve(self.db, tank_id='T-SITE-2', minimum_l=270)
        self.assertAlmostEqual(light['burn_l_per_h'], 15.772, places=3)
        self.assertAlmostEqual(light['hours'], 15.625, places=3)
        self.assertGreater(light['hours'], heavy['hours'])

        committed = commit_hours(self.db, commitment_id='C-1', tank_id='T-SITE',
                                 minimum_hours=14, actor='Commander',
                                 role='incident_commander')
        self.assertEqual(committed['decision'], 'not_committable')
        self.assertAlmostEqual(committed['hours'], 12.5, places=3)

        by_volume = reserve(self.db, tank_id='T-SITE', minimum_l=270,
                            generator_burn_l_per_h=12)
        self.assertAlmostEqual(by_volume['hours'], 20.536, places=3)

    # 5. soil leak ----------------------------------------------------------
    def test_trajectory_soil_leak(self):
        """Supplier shortfall and environmental release settle separately."""
        self.record_delivery()
        self.reconcile()
        self.pass_quality()
        soil = sample(self.db, sample_id='SOIL-1', tank_id='T-SITE', kind='soil',
                      soil_mass_kg=1500, tph_mg_per_kg=4800,
                      density_kg_per_l=0.835, laboratory='Lab A', at=2)
        self.assertEqual(soil['quality'], 'contaminated')
        self.assertAlmostEqual(soil['release_l'], 8.623, places=3)

        environment = report(self.db, tank_id='T-SITE')['environment']
        self.assertAlmostEqual(environment['tank_gap_l'], 20.167, places=3)
        self.assertAlmostEqual(environment['soil_release_l'], 8.623, places=3)
        self.assertAlmostEqual(environment['additional_release_l'], 0.0, places=3)
        self.assertAlmostEqual(environment['release_low_l'], 8.623, places=3)
        self.assertAlmostEqual(environment['release_high_l'], 21.517, places=3)
        self.assertAlmostEqual(environment['disposal_soil_kg'], 1500.0, places=1)
        self.assertAlmostEqual(environment['disposal_water_l'], 2.0, places=1)
        self.assertAlmostEqual(environment['disposal_cost'], 630.30, places=2)

        # supplier is still paid on the metered original, not on the leak
        supplier = report(self.db, tank_id='T-SITE')['supplier']
        self.assertAlmostEqual(supplier['provisional_amount'], 361.92, places=2)
        self.assertIsNone(supplier['calibrated_amount'])

        committed = commit_hours(self.db, commitment_id='C-1', tank_id='T-SITE',
                                 minimum_hours=14, actor='Commander',
                                 role='incident_commander')
        self.assertEqual(committed['decision'], 'committed')
        self.assertAlmostEqual(committed['hours'], 15.625, places=3)

        # a release beyond the unexplained tank gap removes usable fuel
        revised = revise_commitment(self.db, commitment_id='C-1',
                                    actor='Quality Lead', role='quality_lead',
                                    soil_release_l=60, at=3)
        self.assertEqual(revised['decision'], 'commitment_breached')
        self.assertAlmostEqual(revised['tank_gap_l'], 20.167, places=3)
        self.assertAlmostEqual(revised['additional_release_l'], 39.834, places=3)
        self.assertAlmostEqual(revised['usable_l'], 206.604, places=3)
        self.assertAlmostEqual(revised['hours_declared'], 15.625, places=3)
        self.assertAlmostEqual(revised['hours_supported'], 13.099, places=3)
        self.assertAlmostEqual(revised['hours_retracted'], 2.526, places=3)
        self.assertTrue(revised['commitment_breached'])
        self.assertTrue(revised['customer_notice_required'])
        self.assertAlmostEqual(revised['release_high_l'], 61.350, places=3)
        self.assertEqual(revised['environment_disposal_kg'], 1500.0)

    # 6. neighbour transfer -------------------------------------------------
    def test_trajectory_neighbor_sealed_transfer(self):
        """A transfer is authorised only if the donor keeps its own minimum."""
        # the neighbour's own metered delivery, test and quality
        delivery(self.db, delivery_id='D-N', tank_id='T-NEIGHBOR',
                 meter_id='M-NEIGHBOR', vehicle_l=0, vehicle_temp_c=30,
                 driver='B. Driver', seal_id='SEAL-N', seal_confirmed=True,
                 supplier='Fuel Co')
        settle(self.db, settlement_id='S-N', tank_id='T-NEIGHBOR',
               delivery_id='D-N', before_l=490, before_temp_c=30, after_l=490,
               after_temp_c=30, density_kg_per_l=0.835, generator_test_l=0,
               generator_test_hours=1, water_l=0, unextractable_l=0,
               seal_id='SEAL-N', observed_by='Neighbor custodian')
        open_tank(self.db, tank_id='T-UNUSED', capacity_l=1, gauge_l=0,
                  gauge_temp_c=15)  # keep schema warm; not part of the scenario
        self.db.execute("UPDATE fuel_tanks SET minimum_l=300, generator_burn_l_per_h=10, "
                        "minimum_hours=30 WHERE id='T-NEIGHBOR'")
        self.record_delivery()
        self.reconcile()
        self.pass_quality()
        self.pass_quality(tank_id='T-NEIGHBOR', sample_id='Q-N', water_l=0,
                          water_ppm=50)

        donor = reserve(self.db, tank_id='T-NEIGHBOR')
        self.assertTrue(donor['ready'])
        self.assertAlmostEqual(donor['usable_l'], 483.018, places=3)
        self.assertAlmostEqual(donor['hours'], 48.302, places=3)

        blocked = self.authorize('A-BLOCK', 'sealed_transfer', 40,
                                 neighbor_tank_id='T-NEIGHBOR',
                                 quality_cleared=False, seal_id='MOVE-1', at=5)
        self.assertEqual(blocked['decision'], 'quality_unconfirmed')

        too_much = self.authorize('A-BIG', 'sealed_transfer', 200,
                                  neighbor_tank_id='T-NEIGHBOR',
                                  quality_cleared=True, seal_id='MOVE-1', at=5)
        self.assertEqual(too_much['decision'], 'donor_reserve_breach')
        self.assertAlmostEqual(too_much['donor_surplus_l'], 183.018, places=3)

        moved = self.authorize('A-1', 'sealed_transfer', 40,
                               neighbor_tank_id='T-NEIGHBOR',
                               quality_cleared=True, seal_id='MOVE-1', at=5)
        self.assertEqual(moved['decision'], 'authorized')
        self.assertFalse(moved['commitment_suspended'])
        self.assertAlmostEqual(moved['hours_available_now'], 18.161, places=3)
        self.assertAlmostEqual(moved['neighbor_hours_after'], 44.302, places=3)
        self.assertAlmostEqual(moved['transfer_cost'], 82.00, places=2)
        self.assertAlmostEqual(moved['supplier_payable_total'], 361.92, places=2)

        site_after = reserve(self.db, tank_id='T-SITE')
        donor_after = reserve(self.db, tank_id='T-NEIGHBOR')
        self.assertTrue(site_after['ready'])
        self.assertTrue(donor_after['ready'])
        self.assertAlmostEqual(site_after['usable_l'], 286.437, places=3)
        self.assertAlmostEqual(donor_after['usable_l'], 443.018, places=3)

        committed = commit_hours(self.db, commitment_id='C-T', tank_id='T-SITE',
                                 minimum_hours=18, actor='Commander',
                                 role='incident_commander', at=6)
        self.assertEqual(committed['decision'], 'committed')
        self.assertAlmostEqual(committed['hours'], 18.161, places=3)

        # the two contract actions are alternatives: once the transfer closed
        # the deficit, a stop-and-reorder has nothing left to justify
        stop = self.authorize('A-STOP', 'stop_and_reorder', 24,
                              approvals=[{'actor': 'Commander',
                                          'role': 'incident_commander'}], at=7)
        self.assertEqual(stop['decision'], 'no_deficit')

    def test_stop_and_reorder_keeps_neighbor_untouched(self):
        """The other permitted action: suspend the promise, reorder the deficit."""
        self.record_delivery()
        self.reconcile()
        self.pass_quality()

        stop = self.authorize('A-STOP', 'stop_and_reorder', 23,
                              approvals=[{'actor': 'Commander',
                                          'role': 'incident_commander'}], at=5)
        self.assertEqual(stop['decision'], 'insufficient_restoration')
        self.assertAlmostEqual(stop['deficit_l'], 23.563, places=3)

        stop = self.authorize('A-STOP', 'stop_and_reorder', 24,
                              approvals=[{'actor': 'Commander',
                                          'role': 'incident_commander'}], at=5)
        self.assertEqual(stop['decision'], 'authorized')
        self.assertTrue(stop['commitment_suspended'])
        self.assertEqual(stop['hours_available_now'], 0.0)
        self.assertGreater(stop['hours_after_resupply'], 15.625)
        self.assertAlmostEqual(stop['supplier_payable_total'], 406.32, places=2)
        self.assertEqual(stop['transfer_cost'], 0.0)
        self.assertIsNone(stop['neighbor_hours_after'])
        self.assertFalse(stop['calibration_signed'])
        # the neighbour's stock is untouched by this option
        self.assertAlmostEqual(reserve(self.db, tank_id='T-NEIGHBOR')['gauge_l'],
                               490.0, places=3)

    # authority, custody and bypass checks ----------------------------------
    def test_only_authorised_roles_set_replenishment_quantity(self):
        self.record_delivery()
        self.reconcile()
        self.pass_quality()

        driver = self.authorize('A-D', 'stop_and_reorder', 25,
                                approvals=[{'actor': 'A. Driver', 'role': 'driver'}])
        self.assertEqual(driver['decision'], 'unauthorized')

        custodian = self.authorize('A-C', 'sealed_transfer', 40,
                                   approvals=[
                                       {'actor': 'Commander', 'role': 'incident_commander'},
                                       {'actor': 'Custodian', 'role': 'fuel_custodian'},
                                   ], neighbor_tank_id='T-NEIGHBOR',
                                   quality_cleared=True, seal_id='MOVE-X')
        self.assertEqual(custodian['decision'], 'unauthorized')

        excess = self.authorize('A-X', 'stop_and_reorder', 200,
                                approvals=[{'actor': 'Commander',
                                            'role': 'incident_commander'}])
        self.assertEqual(excess['decision'], 'quantity_unjustified')
        self.assertAlmostEqual(excess['max_quantity_l'], 25.919, places=3)

        short = self.authorize('A-S', 'stop_and_reorder', 10,
                               approvals=[{'actor': 'Commander',
                                           'role': 'incident_commander'}])
        self.assertEqual(short['decision'], 'insufficient_restoration')

    def test_driver_signature_is_not_delivered_quantity(self):
        self.record_delivery()
        self.reconcile()
        unlocked = reserve(self.db, tank_id='T-SITE', minimum_l=270,
                           minimum_hours=20, generator_burn_l_per_h=15)
        self.assertEqual(unlocked['decision'], 'short')
        self.assertFalse(unlocked['quality_ok'])
        self.assertAlmostEqual(unlocked['usable_l'], 246.438, places=3)
        self.assertAlmostEqual(unlocked['hours'], 16.429, places=3)

        # no signed ticket may be promoted to "ready" without a passed sample
        committed = commit_hours(self.db, commitment_id='C-RAW', tank_id='T-SITE',
                                 minimum_hours=10, actor='Commander',
                                 role='incident_commander')
        self.assertEqual(committed['decision'], 'not_committable')
        self.assertEqual(committed['reason'], 'quality_unverified')

    def test_custody_seal_required(self):
        missing = delivery(self.db, delivery_id='D-X', tank_id='T-SITE',
                           meter_id='M-SITE', vehicle_l=200, vehicle_temp_c=38,
                           driver='A. Driver', seal_id='', seal_confirmed=True,
                           supplier='Fuel Co')
        self.assertEqual(missing['decision'], 'seal_unconfirmed')
        unsealed = delivery(self.db, delivery_id='D-Y', tank_id='T-SITE',
                            meter_id='M-SITE', vehicle_l=200, vehicle_temp_c=38,
                            driver='A. Driver', seal_id='SEAL-1',
                            seal_confirmed=False, supplier='Fuel Co')
        self.assertEqual(unsealed['decision'], 'seal_unconfirmed')

        self.record_delivery()
        reconciled = self.reconcile()
        self.assertEqual(reconciled['decision'], 'reconciled')
        missing_observer = settle(self.db, settlement_id='S-NO-OBS', tank_id='T-SITE',
                                  delivery_id='D-1', before_l=100, before_temp_c=30,
                                  after_l=260, after_temp_c=30,
                                  density_kg_per_l=0.835, seal_id='SEAL-1',
                                  observed_by='')
        self.assertEqual(missing_observer['decision'], 'custody_unconfirmed')
        wrong_seal = settle(self.db, settlement_id='S-Y', tank_id='T-SITE',
                            delivery_id='D-1', before_l=100, before_temp_c=30,
                            after_l=260, after_temp_c=30, density_kg_per_l=0.835,
                            seal_id='SEAL-OTHER', observed_by='Custodian')
        self.assertEqual(wrong_seal['decision'], 'custody_unconfirmed')
        wrong_gauge = settle(self.db, settlement_id='S-Z', tank_id='T-SITE',
                             delivery_id='D-1', before_l=90, before_temp_c=30,
                             after_l=260, after_temp_c=30, density_kg_per_l=0.835,
                             seal_id='SEAL-1', observed_by='Custodian')
        self.assertEqual(wrong_gauge['decision'], 'gauge_state_mismatch')

    def test_older_fuel_reserve_shortcut_no_longer_marks_ready(self):
        """The provisional 200 L signature cannot mark the site ready."""
        import sqlite3
        from edgehandoff.fuel_reserve import delivery as old_delivery, reserve as old_reserve
        try:
            self.db.execute("INSERT INTO gateways VALUES('g',1)")
            old_delivery(self.db, 'r', 'g', 200)
            self.assertEqual(old_reserve(self.db, 'r', 100)['decision'], 'ready')
        except sqlite3.OperationalError:
            self.skipTest('legacy gateway table shape')
        # the custody reserve for the same physical situation is not ready
        self.assertNotEqual(
            reserve(self.db, tank_id='T-SITE', minimum_l=270)['decision'], 'ready')


if __name__ == '__main__':
    unittest.main()
