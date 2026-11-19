import { test } from 'node:test';
import assert from 'node:assert/strict';
import { groupKey } from '../web/board.mjs';

test('groupKey: arrows move along a two-button group and stop at its ends; Home/End reach the ends', () => {
  assert.equal(groupKey('ArrowRight', 0, 2), 1);
  assert.equal(groupKey('ArrowRight', 1, 2), 1); // no wrap: the last stays
  assert.equal(groupKey('ArrowLeft', 1, 2), 0);
  assert.equal(groupKey('ArrowLeft', 0, 2), 0);
  assert.equal(groupKey('End', 0, 2), 1);
  assert.equal(groupKey('Home', 1, 2), 0);
  assert.equal(groupKey('ArrowDown', 0, 2), -1); // not this group's axis: the browser's
  assert.equal(groupKey('Tab', 0, 2), -1);
  assert.equal(groupKey('ArrowRight', -1, 2), -1); // the key came from outside the members
});

test('groupKey: the jump steps answer up and down only, leaving Home and End to the page', () => {
  const keys = { prev: ['ArrowUp'], next: ['ArrowDown'], ends: false };
  assert.equal(groupKey('ArrowDown', 0, 2, keys), 1);
  assert.equal(groupKey('ArrowUp', 1, 2, keys), 0);
  assert.equal(groupKey('Home', 1, 2, keys), -1);
  assert.equal(groupKey('End', 0, 2, keys), -1);
  assert.equal(groupKey('ArrowLeft', 1, 2, keys), -1);
});

test('groupKey: a two-way switch wraps, so either arrow reaches the other option', () => {
  const keys = { ends: false, wrap: true };
  assert.equal(groupKey('ArrowRight', 1, 2, keys), 0);
  assert.equal(groupKey('ArrowLeft', 0, 2, keys), 1);
  assert.equal(groupKey('ArrowRight', 0, 2, keys), 1);
  assert.equal(groupKey('Home', 1, 2, keys), -1);
});
