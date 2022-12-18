/*
Copyright 2022 The Knative Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

// Slots and counters for Ascii Data:
// 0-31 (32) nonReadableRCharCounter
// 32-47 (16) slots 0-15 respectively
// 48-57 (10) digitCounter
// 58-64 (6) slots 16-22
// 65-90 (26) smallLetterCounter
// 91-96 (6) slots 23-28
// 97-122 (26) capitalLetterCounter
// 123-126 (4) slots 29-32
// 127 (1) nonReadableRCharCounter
// Slots:
//    ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
//    0 1 2 3 4 5 6 7 8 8 9 0 1 2 3 4 5 6 7 8 7 9 0 1 2 1 3 4 5 6 7 6 8 9 0 1 2
// Slots for Ascii 0-127

const ( // Slots for Ascii 0-127

	ExclamationSlot   = iota // 33 (0)
	DoubleQuoteSlot          // 34 (1)
	NumberSlot               // 35
	DollarSlot               // 36
	PercentSlot              // 37
	AmpersandSlot            // 38
	SingleQuoteSlot          // 39
	RoundBracketSlot         // 40, 41
	AsteriskSlot             // 42
	PlusSlot                 // 43 (9)
	CommaSlot                // 44 (10)
	MinusSlot                // 45
	PeriodSlot               // 46
	SlashSlot                // 47
	ColonSlot                // 58 (14)
	SemiSlot                 // 59
	LtGtSlot                 // 60, 62
	EqualSlot                // 61
	QuestionSlot             // 63
	AtSlot                   // 64 (19)
	BackslashSlot            // 92 (20)
	SquareBracketSlot        // 91, 93 (21)
	PowerSlot                // 94
	UnderscoreSlot           // 95
	AccentSlot               // 96
	PipeSlot                 // 124 (25)
	CurlyBracketSlot         // 123, 125 (26)
	HomeSlot                 // 126 (27)
	Unused_1_Slot            // (28)
	Unused_2_Slot            // (29)
	CommentsSlot             // (30)
	HexSlot                  // (31)
	// ---------------------------  up to here are flags
	LetterSlot      // (32)
	DigitSlot       // (33)
	NonReadableSlot // (34)
	SpaceSlot       // (35)
)

var asciiMap [128]uint8 = [128]uint8{
	NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, // 0-7
	NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot,
	NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot,
	NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, NonReadableSlot, // 24-31
	SpaceSlot, ExclamationSlot, DoubleQuoteSlot, NumberSlot, DollarSlot, PercentSlot, AmpersandSlot, SingleQuoteSlot, // 32-39
	RoundBracketSlot, RoundBracketSlot, AsteriskSlot, PlusSlot, CommaSlot, MinusSlot, PeriodSlot, SlashSlot, // 40-47
	DigitSlot, DigitSlot, DigitSlot, DigitSlot, DigitSlot, DigitSlot, DigitSlot, DigitSlot, // 48-55
	DigitSlot, DigitSlot, ColonSlot, SemiSlot, LtGtSlot, EqualSlot, LtGtSlot, QuestionSlot, // 56-63
	AtSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, // 64-71
	LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, // 72-79
	LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, // 80-87
	LetterSlot, LetterSlot, LetterSlot, SquareBracketSlot, BackslashSlot, SquareBracketSlot, PowerSlot, UnderscoreSlot, // 88-95
	AccentSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, // 96-103
	LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, // 104-111
	LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, LetterSlot, // 112-119
	LetterSlot, LetterSlot, LetterSlot, CurlyBracketSlot, PipeSlot, CurlyBracketSlot, HomeSlot, NonReadableSlot, // 120-127
}

const ( // sequence types
	seqNone = iota
	seqLetter
	seqDigit
	seqUnicode
	seqSpace
	seqSpecialChar
	seqNonReadable
)

//////////////////// SimpleValProfile ////////////////

// Exposes ValueProfile interface
type SimpleValProfile struct {
	Digits       CountProfile
	Letters      CountProfile
	Spaces       CountProfile
	SpecialChars CountProfile
	NonReadables CountProfile
	Unicodes     CountProfile
	Sequences    CountProfile
	Flags        AsciiFlagsProfile
	UnicodeFlags FlagSliceProfile
}

// Profile generic value where we expect:
// some short combination of chars
// mainly english letters and/or digits (ascii)
// potentially some small content of special chars
// typically no unicode
func (profile *SimpleValProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(string))
}

func (profile *SimpleValProfile) Profile(str string) {
	var flags uint32
	unicodeFlags := []uint32{}
	digitCounter := uint(0)
	letterCounter := uint(0)
	specialCharCounter := uint(0)
	sequenceCounter := uint(0)
	nonReadableCounter := uint(0)
	spaceCounter := uint(0)
	totalCounter := uint(0)
	unicodeCounter := uint(0)
	var zero, asterisk, slash, minus bool
	seqType := seqNone
	seqPrevType := seqNone
	var asciiType uint8
	for _, c := range str {
		totalCounter++
		if c < 128 { //0-127
			asciiType = asciiMap[c]
			switch asciiType {
			case LetterSlot:
				seqType = seqLetter
				letterCounter++
				if zero && (c == 'X' || c == 'x') {
					flags |= 0x1 << HexSlot
				}
			case DigitSlot:
				seqType = seqDigit
				digitCounter++
			case NonReadableSlot:
				seqType = seqNonReadable
				nonReadableCounter++
			case SpaceSlot:
				seqType = seqSpace
				spaceCounter++
			default:
				seqType = seqSpecialChar
				specialCharCounter++
				flags |= 0x1 << asciiType
				if asterisk && c == '/' {
					flags |= 1 << CommentsSlot
				}
				if slash && c == '*' {
					flags |= 1 << CommentsSlot
				}
				if minus && c == '-' {
					flags |= 1 << CommentsSlot
				}
			}
		} else {
			// Unicode -  128 and onwards

			// Next we use a rough but quick way to profile unicodes using blocks of 128 codes
			// Block 0 is 128-255, block 1 is 256-383...
			// BlockBit represent the bit in a blockElement. Each blockElement carry 64 bits
			seqType = seqUnicode
			unicodeCounter++
			block := (c / 0x80) - 1
			blockBit := int(block & 0x1F)
			blockElement := int(block / 0x20)
			if blockElement >= len(unicodeFlags) {
				// Dynamically allocate as many blockElements as needed for this profile
				unicodeFlags = append(unicodeFlags, make([]uint32, blockElement-len(unicodeFlags)+1)...)
			}
			unicodeFlags[blockElement] |= 0x1 << blockBit
		}

		zero = (c == '0')
		asterisk = (c == '*')
		slash = (c == '/')
		minus = (c == '-')

		if seqType != seqPrevType {
			sequenceCounter++
			seqPrevType = seqType
		}
	}
	if totalCounter > 0xFF {
		totalCounter = 0xFF
		if digitCounter > 0xFF {
			digitCounter = 0xFF
		}
		if letterCounter > 0xFF {
			letterCounter = 0xFF
		}
		if specialCharCounter > 0xFF {
			specialCharCounter = 0xFF
		}
		if unicodeCounter > 0xFF {
			unicodeCounter = 0xFF
		}
		if spaceCounter > 0xFF {
			spaceCounter = 0xFF
		}
		if nonReadableCounter > 0xFF {
			nonReadableCounter = 0xFF
		}
		if sequenceCounter > 0xFF {
			sequenceCounter = 0xFF
		}
	}

	profile.Spaces.Profile(uint8(spaceCounter))
	profile.Unicodes.Profile(uint8(unicodeCounter))
	profile.NonReadables.Profile(uint8(nonReadableCounter))
	profile.Digits.Profile(uint8(digitCounter))
	profile.Letters.Profile(uint8(letterCounter))
	profile.SpecialChars.Profile(uint8(specialCharCounter))
	profile.Sequences.Profile(uint8(sequenceCounter))

	profile.Flags.Profile(flags)
	profile.UnicodeFlags.Profile(unicodeFlags)
}

//////////////////// SimpleValPile ////////////////

// Exposes ValuePile interface
type SimpleValPile struct {
	Digits       CountPile
	Letters      CountPile
	Spaces       CountPile
	SpecialChars CountPile
	NonReadables CountPile
	Unicodes     CountPile
	Sequences    CountPile
	Flags        AsciiFlagsPile
	UnicodeFlags FlagSlicePile
}

func (pile *SimpleValPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*SimpleValProfile))
}

func (pile *SimpleValPile) Add(profile *SimpleValProfile) {
	pile.Letters.Add(profile.Letters)
	pile.Digits.Add(profile.Digits)
	pile.Spaces.Add(profile.Spaces)
	pile.SpecialChars.Add(profile.SpecialChars)
	pile.NonReadables.Add(profile.NonReadables)
	pile.Unicodes.Add(profile.Unicodes)
	pile.Sequences.Add(profile.Sequences)
	pile.Flags.Add(profile.Flags)
	pile.UnicodeFlags.Add(profile.UnicodeFlags)
}

func (pile *SimpleValPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*SimpleValPile))
}

func (pile *SimpleValPile) Merge(otherPile *SimpleValPile) {
	pile.Digits.Merge(otherPile.Digits)
	pile.Letters.Merge(otherPile.Letters)
	pile.Spaces.Merge(otherPile.Spaces)
	pile.SpecialChars.Merge(otherPile.SpecialChars)
	pile.NonReadables.Merge(otherPile.NonReadables)
	pile.Unicodes.Merge(otherPile.Unicodes)
	pile.Sequences.Merge(otherPile.Sequences)
	pile.Flags.Merge(otherPile.Flags)
	pile.UnicodeFlags.Merge(otherPile.UnicodeFlags)
}

func (pile *SimpleValPile) Clear() {
	pile.Digits.Clear()
	pile.Letters.Clear()
	pile.Spaces.Clear()
	pile.SpecialChars.Clear()
	pile.NonReadables.Clear()
	pile.Unicodes.Clear()
	pile.Sequences.Clear()
	pile.Flags.Clear()
	pile.UnicodeFlags.Clear()
}

//////////////////// SimpleValConfig ////////////////

// Exposes ValueConfig interface
type SimpleValConfig struct {
	Digits       CountConfig      `json:"digits"`
	Letters      CountConfig      `json:"letters"`
	Spaces       CountConfig      `json:"spaces"`
	SpecialChars CountConfig      `json:"schars"`
	NonReadables CountConfig      `json:"nonreadables"`
	Unicodes     CountConfig      `json:"unicodes"`
	Sequences    CountConfig      `json:"sequences"`
	Flags        AsciiFlagsConfig `json:"flags"`
	UnicodeFlags FlagSliceConfig  `json:"unicodeFlags"`
	//Mandatory    bool           `json:"mandatory"`
}

func (config *SimpleValConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*SimpleValPile))
}
func (config *SimpleValConfig) Learn(pile *SimpleValPile) {
	config.Digits.Learn(pile.Digits)
	config.Letters.Learn(pile.Letters)
	config.Spaces.Learn(pile.Spaces)
	config.SpecialChars.Learn(pile.SpecialChars)
	config.NonReadables.Learn(pile.NonReadables)
	config.Unicodes.Learn(pile.Unicodes)
	config.Sequences.Learn(pile.Sequences)
	config.Flags.Learn(pile.Flags)
	config.UnicodeFlags.Learn(pile.UnicodeFlags)
}

func (config *SimpleValConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(otherValConfig.(*SimpleValConfig))
}

func (config *SimpleValConfig) Fuse(otherConfig *SimpleValConfig) {
	config.Digits.Fuse(otherConfig.Digits)
	config.Letters.Fuse(otherConfig.Letters)
	config.Spaces.Fuse(otherConfig.Spaces)
	config.SpecialChars.Fuse(otherConfig.SpecialChars)
	config.NonReadables.Fuse(otherConfig.NonReadables)
	config.Unicodes.Fuse(otherConfig.Unicodes)
	config.Sequences.Fuse(otherConfig.Sequences)
	config.Flags.Fuse(otherConfig.Flags)
	config.UnicodeFlags.Fuse(otherConfig.UnicodeFlags)
}

func (config *SimpleValConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*SimpleValProfile))
}

func (config *SimpleValConfig) Decide(profile *SimpleValProfile) *Decision {
	var current *Decision
	DecideChild(&current, config.Letters.Decide(profile.Letters), "Letters")
	DecideChild(&current, config.Digits.Decide(profile.Digits), "Digits")
	DecideChild(&current, config.Spaces.Decide(profile.Spaces), "Spaces")
	DecideChild(&current, config.SpecialChars.Decide(profile.SpecialChars), "SpecialChars")
	DecideChild(&current, config.NonReadables.Decide(profile.NonReadables), "NonReadables")
	DecideChild(&current, config.Unicodes.Decide(profile.Unicodes), "Unicodes")
	DecideChild(&current, config.Sequences.Decide(profile.Sequences), "Sequences")
	DecideChild(&current, config.Flags.Decide(profile.Flags), "Special Chars Used")
	DecideChild(&current, config.UnicodeFlags.Decide(profile.UnicodeFlags), "Unicode Blocks")
	return current
}

func (config *SimpleValConfig) Prepare() {
	config.Digits.Prepare()
	config.Letters.Prepare()
	config.Spaces.Prepare()
	config.SpecialChars.Prepare()
	config.NonReadables.Prepare()
	config.Unicodes.Prepare()
	config.Sequences.Prepare()
	config.Flags.Prepare()
	config.UnicodeFlags.Prepare()
}
