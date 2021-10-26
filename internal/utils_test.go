package internal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/internal"
)

func TestPaddedLen(t *testing.T) {
	assert.EqualValues(t, 0, internal.PaddedLen(0, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(1, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(2, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(3, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(4, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(5, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(6, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(7, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(8, 4))

	assert.EqualValues(t, 0, internal.PaddedLen(0, 5))
	assert.EqualValues(t, 5, internal.PaddedLen(5, 5))
	assert.EqualValues(t, 10, internal.PaddedLen(8, 5))
}
