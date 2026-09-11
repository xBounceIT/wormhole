package vt10x

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateStrings(t *testing.T) {
	var st State
	st.RecordHistory = true

	term, err := Create(&st, nil)
	require.NoError(t, err, "terminal created")
	term.Resize(6, 3)

	_, err = term.Write([]byte("\x1b"))
	assert.False(t, st.HasStringBeforeCursor("hi", false), "not to match anything")
	assert.Equal(t, "\n", st.StringBeforeCursor(), "empty string")
	_, err = term.Write([]byte("[1;1H"))
	assert.False(t, st.HasStringBeforeCursor("hi", false), "expect still not to match anything")
	assert.Equal(t, "\n", st.StringBeforeCursor(), "empty string 2")

	_, err = term.Write([]byte("      world\033[1;1Hhello\033[2;6H"))
	require.NoError(t, err, "write hello world")
	cx, cy := st.Cursor()
	assert.Equal(t, 5, cx, "col after hello world")
	assert.Equal(t, 1, cy, "row after hello world")
	gx1, gy1 := st.GlobalCursor()
	assert.Equal(t, 5, gx1, "global col after hello world")
	assert.Equal(t, 1, gy1, "global row after hello world")

	assert.True(t, st.HasStringBeforeCursor("hello world", false), "expected hello world")
	assert.False(t, st.HasStringBeforeCursor("hallo welt", false), "did not expect hallo welt")
	assert.False(t, st.HasStringBeforeCursor("hallo welt", true), "did not expect hallo welt in long string")
	assert.Equal(t, "hello \nworld\n", st.StringBeforeCursor())
	assert.Equal(t, "hello world", st.UnwrappedStringBeforeCursor())
	assert.Equal(t, "orld", st.UnwrappedStringToCursorFrom(1, 1))
	assert.Equal(t, "llo \nworld\n", st.StringToCursorFrom(0, 2))
	assert.Equal(t, "", st.UnwrappedStringToCursorFrom(2, 1))
	assert.Equal(t, "hello \nworld \n      \n", st.String(), "full terminal")

	// fill first two lines
	_, err = term.Write([]byte("!"))
	require.NoError(t, err, "write space")
	cx, cy = st.Cursor()
	assert.Equal(t, 5, cx, "col after !")
	assert.Equal(t, 1, cy, "row after !")
	gx2, gy2 := st.GlobalCursor()
	assert.Equal(t, 6, gx2, "global col after !")
	assert.Equal(t, 1, gy2, "global row after !")
	assert.Equal(t, "hello \nworld!\n", st.StringBeforeCursor())
	assert.Equal(t, "hello world!", st.UnwrappedStringBeforeCursor())
	assert.True(t, st.HasStringBeforeCursor("hello world!", false), "expected hello world!")
	assert.Equal(t, "!", st.UnwrappedStringToCursorFrom(gy1, gx1))
	assert.Equal(t, "hello \nworld!\n      \n", st.String(), "full terminal")

	// scroll hello out of view
	_, err = term.Write([]byte("l1\n\rl2"))
	require.NoError(t, err, "write two more lines")
	cx, cy = st.Cursor()
	assert.Equal(t, 2, cx, "col after two more lines")
	assert.Equal(t, 2, cy, "row after two more")
	gx3, gy3 := st.GlobalCursor()
	assert.Equal(t, 2, gx3, "global col after two more lines")
	assert.Equal(t, 3, gy3, "global row after two more lines")
	assert.Equal(t, "world!\nl1    \nl2    \n", st.String(), "full terminal")
	assert.Equal(t, "l1    l2", st.UnwrappedStringToCursorFrom(gy2, gx2))
	assert.Equal(t, "!l1    l2", st.UnwrappedStringToCursorFrom(gy1, gx1))
	assert.Equal(t, "llo world!l1    l2", st.UnwrappedStringToCursorFrom(0, 2))
	assert.Equal(t, "world!l1    l2", st.UnwrappedStringBeforeCursor())
	assert.Equal(t, "world!\nl1    \nl2\n", st.StringBeforeCursor())
	assert.True(t, st.HasStringBeforeCursor("l2", false), "expected l2")
	assert.True(t, st.HasStringBeforeCursor("hello world!\nl1\nl2", true), "expected hello world!\\nl1\\nl2")

	// add another line scroll world! out of view
	_, err = term.Write([]byte("\n\rl3"))
	require.NoError(t, err, "write another")
	cx, cy = st.Cursor()
	assert.Equal(t, 2, cx, "col after three lines added")
	assert.Equal(t, 2, cy, "row after three lines added")
	gx4, gy4 := st.GlobalCursor()
	assert.Equal(t, 2, gx4, "global col after three lines added")
	assert.Equal(t, 4, gy4, "global row after three lines added")
	assert.Equal(t, "l1    \nl2    \nl3    \n", st.String(), "full terminal")
	assert.Equal(t, "    l3", st.UnwrappedStringToCursorFrom(gy3, gx3))
	assert.Equal(t, "l1    l2    l3", st.UnwrappedStringToCursorFrom(gy2, gx2))
	assert.Equal(t, "!l1    l2    l3", st.UnwrappedStringToCursorFrom(gy1, gx1))
	assert.Equal(t, "llo world!l1    l2    l3", st.UnwrappedStringToCursorFrom(0, 2))
	assert.Equal(t, "llo \nworld!\nl1    \nl2    \nl3\n", st.StringToCursorFrom(0, 2))
	assert.Equal(t, "l1    l2    l3", st.UnwrappedStringToCursorFrom(-1, 0))
	assert.Equal(t, "l1    l2    l3", st.UnwrappedStringBeforeCursor())
	assert.Equal(t, "l1    \nl2    \nl3\n", st.StringBeforeCursor())
	assert.True(t, st.HasStringBeforeCursor("l3", false), "expected l3")
	assert.True(t, st.HasStringBeforeCursor("hello world!l1    l2    l3", false), "expected everything")
	assert.True(t, st.HasStringBeforeCursor("hello world!l1\r\nl2 \r\nl3", true), "expected everything in long string")
	assert.False(t, st.HasStringBeforeCursor("hallo welt!l1    l2    l3", false), "did not expect hello welt")
	assert.False(t, st.HasStringBeforeCursor("hallo welt!l1\r\nl2 \r\nl3", true), "did not expect hello welt in long string")
}
