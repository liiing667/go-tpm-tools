// Package cmd contains a CLI to interact with TPM.
package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
)

type gotpmOptions struct {
	tpmPath   string
	quiet     bool
	verbose   bool
	stdout    io.Writer
	runToken  tokenRunner
	tpmOpener func(tpmPath string) (io.ReadWriteCloser, error)
}

// NewGotpmCmd returns the entrypoint for gotpm.
func NewGotpmCmd() *cobra.Command {
	return newGotpmCmd(openImpl)
}

func newGotpmCmd(tpmOpener func(tpmPath string) (io.ReadWriteCloser, error)) *cobra.Command {
	o := &gotpmOptions{
		tpmOpener: tpmOpener,
		stdout:    os.Stdout,
		runToken:  runToken,
	}
	return newGotpmCommand(o)
}

func newGotpmCommand(o *gotpmOptions) *cobra.Command {
	if o == nil {
		o = &gotpmOptions{}
	}
	if o.stdout == nil {
		o.stdout = os.Stdout
	}
	if o.runToken == nil {
		o.runToken = runToken
	}
	root := &cobra.Command{
		Use: "gotpm",
		Long: `Command line tool for the go-tpm TSS

This tool allows performing TPM2 operations from the command line.
See the per-command documentation for more information.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			o.stdout = cmd.OutOrStdout()
			if o.quiet && o.verbose {
				return fmt.Errorf("cannot specify both --quiet and --verbose")
			}
			cmd.SilenceUsage = true
			return nil
		},
	}
	root.PersistentFlags().BoolVar(&o.quiet, "quiet", false,
		"print nothing if command is successful")
	root.PersistentFlags().BoolVar(&o.verbose, "verbose", false,
		"print additional info to stdout")
	o.addTPMPathFlag(root)
	hideHelp(root)
	root.AddCommand(
		newAttestCmd(o),
		newFlushCmd(o),
		newPubkeyCmd(o),
		newReadCmd(o),
		newRegisterCmd(o),
		newSealCmd(o),
		newUnsealCmd(o),
		newTokenCmd(o),
		newVerifyCmd(),
	)
	return root
}

var (
	quiet   bool
	verbose bool
)

func messageOutput() io.Writer {
	if quiet {
		return io.Discard
	}
	return os.Stdout
}

func debugOutput() io.Writer {
	if verbose {
		return os.Stdout
	}
	return io.Discard
}

func (o *gotpmOptions) messageOutput() io.Writer {
	if o == nil {
		return messageOutput()
	}
	if o.quiet {
		return io.Discard
	}
	if o.stdout != nil {
		return o.stdout
	}
	return os.Stdout
}

func (o *gotpmOptions) debugOutput() io.Writer {
	if o == nil {
		return debugOutput()
	}
	if !o.verbose {
		return io.Discard
	}
	if o.stdout != nil {
		return o.stdout
	}
	return os.Stdout
}

// Default Text Marshalling options
var marshalOptions = prototext.MarshalOptions{
	Multiline: true,
	EmitASCII: true,
}
var unmarshalOptions = prototext.UnmarshalOptions{}
