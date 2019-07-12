use parity_codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};
use support::{StorageValue, dispatch::Result, decl_module, decl_storage, decl_event};
use system::{ensure_signed, ensure_root};
use runtime_primitives::weights::TransactionWeight;

/// Our module's configuration trait. All our types and consts go in here. If the
/// module is dependent on specific other modules, then their configuration traits
/// should be added to our implied traits list.
///
/// `system::Trait` should always be included in our implied traits.
pub trait Trait: balances::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_event!(
	/// Events are a simple means of reporting specific conditions and
	/// circumstances that have happened that users, Dapps and/or chain explorers would find
	/// interesting and otherwise difficult to detect.
	pub enum Event<T> where B = <T as balances::Trait>::Balance {
		// Just a normal `enum`, here's a dummy event to ensure it compiles.
		/// Dummy event, just here so there's a generic type that's used.
		Dummy(B),
	}
);

/// Number of horizontal tiles on the grid.
pub const GRID_WIDTH: u32 = 22;
/// Number of vertical tiles on the grid.
pub const GRID_HEIGHT: u32 = 22;

/// Color of a tile of the grid.
#[derive(Copy, Clone, PartialEq, Eq, Decode, Encode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
pub enum Color {
	Empty,
	Red,		// Horizontal
	Yellow,		// The "T"
	Green,		// Stair where right goes up
	Cyan,		// Stair where left goes up
	Blue,		// Square
	White,		// Reverse "L"
	Pink,		// The "L"
}

impl Default for Color {
	fn default() -> Color {
		Color::Empty
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as Example {
		/// For each [x, y] coordinate, the color of the grid at this position.
		Grid get(grid) config(): map [u32; 2] => Color;
	}
}

// The module declaration. This states the entry points that we handle. The
// macro takes care of the marshalling of arguments and dispatch.
//
// Anyone can have these functions execute by signing and submitting
// an extrinsic. Ensure that calls into each of these execute in a time, memory and
// using storage space proportional to any costs paid for by the caller or otherwise the
// difficulty of forcing the call to happen.
//
// Generally you'll want to split these into three groups:
// - Public calls that are signed by an external account.
// - Root calls that are allowed to be made only by the governance system.
// - Unsigned calls that can be of two kinds:
//   * "Inherent extrinsics" that are opinions generally held by the block
//     authors that build child blocks.
//   * Unsigned Transactions that are of intrinsic recognisable utility to the
//     network, and are validated by the runtime.
//
// Information about where this dispatch initiated from is provided as the first argument
// "origin". As such functions must always look like:
//
// `fn foo(origin, bar: Bar, baz: Baz) -> Result;`
//
// The `Result` is required as part of the syntax (and expands to the conventional dispatch
// result of `Result<(), &'static str>`).
//
// When you come to `impl` them later in the module, you must specify the full type for `origin`:
//
// `fn foo(origin: T::Origin, bar: Bar, baz: Baz) { ... }`
//
// There are three entries in the `system::Origin` enum that correspond
// to the above bullets: `::Signed(AccountId)`, `::Root` and `::None`. You should always match
// against them as the first thing you do in your function. There are three convenience calls
// in system that do the matching for you and return a convenient result: `ensure_signed`,
// `ensure_root` and `ensure_none`.
decl_module! {
	// Simple declaration of the `Module` type. Lets the macro know what its working on.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		/// Deposit one of this module's events by using the default implementation.
		/// It is also possible to provide a custom implementation.
		/// For non-generic events, the generic parameter just needs to be dropped, so that it
		/// looks like: `fn deposit_event() = default;`.
		fn deposit_event<T>() = default;
		/// This is your public interface. Be extremely careful.
		/// This is just a simple example of how to interact with the module from the external
		/// world.
		// This just increases the value of `Dummy` by `increase_by`.
		//
		// Since this is a dispatched function there are two extremely important things to
		// remember:
		//
		// - MUST NOT PANIC: Under no circumstances (save, perhaps, storage getting into an
		// irreparably damaged state) must this function panic.
		// - NO SIDE-EFFECTS ON ERROR: This function must either complete totally (and return
		// `Ok(())` or it must have no side-effects on storage and return `Err('Some reason')`.
		//
		// The first is relatively easy to audit for - just ensure all panickers are removed from
		// logic that executes in production (which you do anyway, right?!). To ensure the second
		// is followed, you should do all tests for validity at the top of your function. This
		// is stuff like checking the sender (`origin`) or that state is such that the operation
		// makes sense.
		//
		// Once you've determined that it's all good, then enact the operation and change storage.
		// If you can't be certain that the operation will succeed without substantial computation
		// then you have a classic blockchain attack scenario. The normal way of managing this is
		// to attach a bond to the operation. As the first major alteration of storage, reserve
		// some value from the sender's account (`Balances` module has a `reserve` function for
		// exactly this scenario). This amount should be enough to cover any costs of the
		// substantial execution in case it turns out that you can't proceed with the operation.
		//
		// If it eventually transpires that the operation is fine and, therefore, that the
		// expense of the checks should be borne by the network, then you can refund the reserved
		// deposit. If, however, the operation turns out to be invalid and the computation is
		// wasted, then you can burn it or repatriate elsewhere.
		//
		// Security bonds ensure that attackers can't game it by ensuring that anyone interacting
		// with the system either progresses it or pays for the trouble of faffing around with
		// no progress.
		//
		// If you don't respect these rules, it is likely that your chain will be attackable.
		//
		// Each transaction can optionally indicate a weight. The weight is passed in as a
		// custom attribute and the value can be anything that implements the `Weighable`
		// trait. Most often using substrate's default `TransactionWeight` is enough for you.
		//
		// A basic weight is a tuple of `(base_weight, byte_weight)`. Upon including each transaction
		// in a block, the final weight is calculated as `base_weight + byte_weight * tx_size`.
		// If this value, added to the weight of all included transactions, exceeds `MAX_TRANSACTION_WEIGHT`,
		// the transaction is not included. If no weight attribute is provided, the `::default()`
		// implementation of `TransactionWeight` is used.
		//
		// The example below showcases a transaction which is relatively costly, but less dependent on
		// the input, hence `byte_weight` is configured smaller.
		#[weight = TransactionWeight::Basic(100_000, 10)]
		fn accumulate_dummy(origin, increase_by: T::Balance) -> Result {
			// This is a public call, so we ensure that the origin is some signed account.
			let _sender = ensure_signed(origin)?;

			// Read the value of dummy from storage.
			// let dummy = Self::dummy();
			// Will also work using the `::get` on the storage item type itself:
			// let dummy = <Dummy<T>>::get();

			// Calculate the new value.
			// let new_dummy = dummy.map_or(increase_by, |dummy| dummy + increase_by);

			// Put the new value into storage.
			// <Dummy<T>>::put(new_dummy);
			// Will also work with a reference:
			// <Dummy<T>>::put(&new_dummy);

			// Here's the new one of read and then modify the value.
			<Dummy<T>>::mutate(|dummy| {
				let new_dummy = dummy.map_or(increase_by, |dummy| dummy + increase_by);
				*dummy = Some(new_dummy);
			});

			// All good.
			Ok(())
		}

		/// A privileged call; in this case it resets our dummy value to something new.
		// Implementation of a privileged call. The `origin` parameter is ROOT because
		// it's not (directly) from an extrinsic, but rather the system as a whole has decided
		// to execute it. Different runtimes have different reasons for allow privileged
		// calls to be executed - we don't need to care why. Because it's privileged, we can
		// assume it's a one-off operation and substantial processing/storage/memory can be used
		// without worrying about gameability or attack scenarios.
		// If you not specify `Result` explicitly as return value, it will be added automatically
		// for you and `Ok(())` will be returned.
		fn set_dummy(origin, #[compact] new_value: T::Balance) {
			ensure_root(origin)?;
			// Put the new value into storage.
			<Dummy<T>>::put(new_value);
		}

		// The signature could also look like: `fn on_initialize()`
		fn on_initialize(_n: T::BlockNumber) {
			// Anything that needs to be done at the start of the block.
			// We don't do anything here.
		}

		// The signature could also look like: `fn on_finalize()`
		fn on_finalize(_n: T::BlockNumber) {
			// Anything that needs to be done at the end of the block.
			// We just kill our dummy storage item.
			<Dummy<T>>::kill();
		}

		// A runtime code run after every block and have access to extended set of APIs.
		//
		// For instance you can generate extrinsics for the upcoming produced block.
		fn offchain_worker(_n: T::BlockNumber) {
			// We don't do anything here.
			// but we could dispatch extrinsic (transaction/unsigned/inherent) using
			// runtime_io::submit_extrinsic
		}
	}
}
