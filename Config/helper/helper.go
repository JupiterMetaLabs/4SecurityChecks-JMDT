package helper
import(
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/jupitermetalabs/jmdt4checks/Config"
)
func ConvertAccessList(al Config.AccessList) types.AccessList {
    var tal types.AccessList
    for _, tuple := range al {
        tal = append(tal, types.AccessTuple{
            Address:     tuple.Address,
            StorageKeys: tuple.StorageKeys,
        })
    }
    return tal
}